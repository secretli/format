// Package transfer hands a share link from one device to another with a
// short code like 7-acid-rocket, through the server's relay. FORMAT.md
// section 11.
//
// The relay carries three legs: the sender's CPace share (the offer), the
// receiver's share with a tag proving it derived the same key (the answer),
// and only then the link, sealed for the receiver (the delivery). The relay
// sees public shares, a tag and a fixed-size ciphertext; the words never
// leave the two devices. Send and Receive run the two roles over any relay
// that implements SenderRelay and ReceiverRelay.
package transfer

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/secretli/format/go/cpace"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// SIDSize is the size of the session id, which is also the transfer's id
	// at the relay.
	SIDSize = 32
	// PlaintextSize is what the link is padded to, so that its length does
	// not reach the relay.
	PlaintextSize = 512
	// MaxLinkSize is the longest link that fits: the plaintext less its
	// two-byte length prefix.
	MaxLinkSize = PlaintextSize - lengthPrefixSize
	// SealedSize is the delivery leg: nonce, ciphertext and tag.
	SealedSize = chacha20poly1305.NonceSizeX + PlaintextSize + chacha20poly1305.Overhead
	// ConfirmationSize is the receiver's tag in the answer leg.
	ConfirmationSize = 32

	lengthPrefixSize = 2
	keySize          = 32
)

var (
	adSender    = []byte("sender")
	adReceiver  = []byte("receiver")
	confirmInfo = "secretli transfer v1 confirm"
	payloadInfo = "secretli transfer v1 payload"
	payloadAAD  = []byte("payload")
)

var (
	// ErrCodeMismatch means the two sides used different codes. Nothing was
	// delivered, and the transfer is closed.
	ErrCodeMismatch = errors.New("the code did not match")
	// ErrLinkTooLong is a link longer than MaxLinkSize.
	ErrLinkTooLong = errors.New("link is too long to transfer")
)

// CloseReason is why a side ends a transfer early; delivering ends it as done.
type CloseReason string

const (
	Cancelled CloseReason = "cancelled"
	Mismatch  CloseReason = "mismatch"
)

// EndedError is what a relay returns when the other side ended the transfer,
// or it expired. Receive turns a "mismatch" into ErrCodeMismatch.
type EndedError struct {
	Reason string
}

func (e *EndedError) Error() string { return "transfer ended: " + e.Reason }

// Answer is the receiver's leg: its CPace share and its proof of the same key.
type Answer struct {
	Share        []byte
	Confirmation []byte
}

// SenderRelay is the relay as the sender uses it, once the transfer holds
// its offer.
type SenderRelay interface {
	// AwaitAnswer returns the receiver's answer once it exists.
	AwaitAnswer(ctx context.Context) (Answer, error)
	// Deliver stores the sealed link, which ends the transfer as done.
	Deliver(ctx context.Context, sealed []byte) error
	Close(ctx context.Context, reason CloseReason) error
}

// ReceiverRelay is the relay as the receiver uses it, after claiming the
// transfer.
type ReceiverRelay interface {
	Answer(ctx context.Context, answer Answer) error
	// AwaitDelivery returns the sealed link once the sender delivered it.
	AwaitDelivery(ctx context.Context) ([]byte, error)
	Close(ctx context.Context, reason CloseReason) error
}

// Party is what both sides must agree on; only the words are secret.
type Party struct {
	Words [2]string
	// SID is the session id, which the sender draws with NewSID.
	SID []byte
	// Origin is the server's origin, such as https://secretli.app.
	Origin string
}

// Offer is the sender's first leg, kept until the answer arrives.
type Offer struct {
	// Share goes to the relay when the transfer is opened.
	Share  []byte
	scalar []byte
}

// NewSID draws a session id for a new transfer.
func NewSID() ([]byte, error) {
	sid := make([]byte, SIDSize)
	if _, err := rand.Read(sid); err != nil {
		return nil, fmt.Errorf("draw session id: %w", err)
	}
	return sid, nil
}

// ChannelIdentifier is CPace's channel identifier: it binds a run to this
// protocol version and to the server.
func ChannelIdentifier(origin string) []byte {
	return []byte("secretli-transfer-v1 " + origin)
}

// Generator is the CPace generator for a party.
func Generator(p Party) []byte {
	return cpace.Generator(Password(p.Words), ChannelIdentifier(p.Origin), p.SID)
}

// Keys are the two keys derived from CPace's intermediate session key.
type Keys struct {
	Confirm []byte
	Payload []byte
}

// DeriveKeys derives the confirmation and payload keys with HKDF-SHA512,
// salted with the session id.
func DeriveKeys(isk, sid []byte) (Keys, error) {
	confirm, err := hkdf.Key(sha512.New, isk, sid, confirmInfo, keySize)
	if err != nil {
		return Keys{}, fmt.Errorf("derive confirmation key: %w", err)
	}
	payload, err := hkdf.Key(sha512.New, isk, sid, payloadInfo, keySize)
	if err != nil {
		return Keys{}, fmt.Errorf("derive payload key: %w", err)
	}
	return Keys{Confirm: confirm, Payload: payload}, nil
}

// SessionKeys runs the key schedule from the shared point K and both shares.
func SessionKeys(sid, k, senderShare, receiverShare []byte) (Keys, error) {
	return DeriveKeys(cpace.ISK(sid, k, senderShare, adSender, receiverShare, adReceiver), sid)
}

// ConfirmationTag is the receiver's proof that it derived the same key:
// HMAC-SHA512 over "receiver" and both shares, truncated to 32 bytes.
func ConfirmationTag(key, senderShare, receiverShare []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(adReceiver)
	mac.Write(senderShare)
	mac.Write(receiverShare)
	return mac.Sum(nil)[:ConfirmationSize]
}

// Seal pads the link to PlaintextSize and seals it as nonce || ciphertext,
// always SealedSize bytes.
func Seal(key, sid []byte, link string) ([]byte, error) {
	if len(link) > MaxLinkSize {
		return nil, ErrLinkTooLong
	}
	plaintext := make([]byte, PlaintextSize)
	binary.BigEndian.PutUint16(plaintext, uint16(len(link))) // #nosec G115 -- at most MaxLinkSize
	copy(plaintext[lengthPrefixSize:], link)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("payload cipher: %w", err)
	}
	out := make([]byte, chacha20poly1305.NonceSizeX, SealedSize)
	if _, err := rand.Read(out); err != nil {
		return nil, fmt.Errorf("draw nonce: %w", err)
	}
	return aead.Seal(out, out, plaintext, sealAAD(sid)), nil
}

// Open opens a sealed link. Any failure means the keys differed, and is
// ErrCodeMismatch.
func Open(key, sid, sealed []byte) (string, error) {
	if len(sealed) != SealedSize {
		return "", ErrCodeMismatch
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("payload cipher: %w", err)
	}
	nonce, ciphertext := sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, sealAAD(sid))
	if err != nil {
		return "", ErrCodeMismatch
	}
	n := int(binary.BigEndian.Uint16(plaintext))
	if n > MaxLinkSize {
		return "", ErrCodeMismatch
	}
	return string(plaintext[lengthPrefixSize : lengthPrefixSize+n]), nil
}

func sealAAD(sid []byte) []byte {
	return append(append([]byte{}, sid...), payloadAAD...)
}

// NewOffer is the sender's first leg: its CPace share, computed before the
// transfer exists at the relay.
func NewOffer(p Party) (*Offer, error) {
	scalar, err := cpace.SampleScalar()
	if err != nil {
		return nil, err
	}
	share, err := cpace.Share(Generator(p), scalar)
	if err != nil {
		return nil, err
	}
	return &Offer{Share: share, scalar: scalar}, nil
}

// Send is the sender's role: it hands the link over only after the
// receiver's confirmation tag proves it typed the same code. A wrong code
// closes the transfer as a mismatch and returns ErrCodeMismatch.
func Send(ctx context.Context, relay SenderRelay, p Party, offer *Offer, link string) error {
	if len(link) > MaxLinkSize {
		return ErrLinkTooLong
	}
	answer, err := relay.AwaitAnswer(ctx)
	if err != nil {
		return err
	}
	k, err := cpace.ScalarMultVfy(offer.scalar, answer.Share)
	if errors.Is(err, cpace.ErrInvalidShare) {
		return mismatch(ctx, relay)
	}
	if err != nil {
		return err
	}
	keys, err := SessionKeys(p.SID, k, offer.Share, answer.Share)
	if err != nil {
		return err
	}
	if !hmac.Equal(answer.Confirmation, ConfirmationTag(keys.Confirm, offer.Share, answer.Share)) {
		return mismatch(ctx, relay)
	}
	sealed, err := Seal(keys.Payload, p.SID, link)
	if err != nil {
		return err
	}
	return relay.Deliver(ctx, sealed)
}

// Receive is the receiver's role: it answers the offer, proving knowledge
// of the code, then opens the link. A wrong code on either side returns
// ErrCodeMismatch.
func Receive(ctx context.Context, relay ReceiverRelay, p Party, offer []byte) (string, error) {
	scalar, err := cpace.SampleScalar()
	if err != nil {
		return "", err
	}
	share, err := cpace.Share(Generator(p), scalar)
	if err != nil {
		return "", err
	}
	k, err := cpace.ScalarMultVfy(scalar, offer)
	if errors.Is(err, cpace.ErrInvalidShare) {
		return "", mismatch(ctx, relay)
	}
	if err != nil {
		return "", err
	}
	keys, err := SessionKeys(p.SID, k, offer, share)
	if err != nil {
		return "", err
	}
	answer := Answer{Share: share, Confirmation: ConfirmationTag(keys.Confirm, offer, share)}
	if err := relay.Answer(ctx, answer); err != nil {
		return "", err
	}
	sealed, err := relay.AwaitDelivery(ctx)
	if err != nil {
		if ended, ok := errors.AsType[*EndedError](err); ok && ended.Reason == string(Mismatch) {
			return "", ErrCodeMismatch
		}
		return "", err
	}
	return Open(keys.Payload, p.SID, sealed)
}

// mismatch closes the transfer as a mismatch and returns ErrCodeMismatch. A
// failed close is ignored: the transfer may already be gone, and the
// mismatch is what the caller needs to hear.
func mismatch(ctx context.Context, relay interface {
	Close(context.Context, CloseReason) error
}) error {
	_ = relay.Close(ctx, Mismatch)
	return ErrCodeMismatch
}
