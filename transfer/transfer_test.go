package transfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testLink   = "https://secretli.example/s#AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbCdE"
	testOrigin = "https://secretli.example"
)

var testSID = randomBytes(SIDSize)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// relayPair is both sides' views of one in-memory transfer, with the
// server's rules: legs written once, delivering ends the transfer, a close
// the other side sees, and waits that block until their leg exists.
type relayPair struct {
	mu       sync.Mutex
	changed  chan struct{}
	answer   *Answer
	delivery []byte
	closed   string
}

func newRelayPair() *relayPair { return &relayPair{changed: make(chan struct{})} }

func (r *relayPair) notifyLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// waitFor hands out a written leg even after the transfer closed.
func waitFor[T any](ctx context.Context, r *relayPair, read func() (T, bool)) (T, error) {
	for {
		r.mu.Lock()
		value, ok := read()
		closed, changed := r.closed, r.changed
		r.mu.Unlock()
		if ok {
			return value, nil
		}
		if closed != "" {
			return value, &EndedError{Reason: closed}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return value, ctx.Err()
		}
	}
}

func (r *relayPair) Close(_ context.Context, reason CloseReason) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed == "" {
		r.closed = string(reason)
	}
	r.notifyLocked()
	return nil
}

func (r *relayPair) closedWith() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

type senderSide struct{ *relayPair }

func (s senderSide) AwaitAnswer(ctx context.Context) (Answer, error) {
	return waitFor(ctx, s.relayPair, func() (Answer, bool) {
		if s.answer == nil {
			return Answer{}, false
		}
		return *s.answer, true
	})
}

func (s senderSide) Deliver(_ context.Context, sealed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed != "" {
		return &EndedError{Reason: s.closed}
	}
	s.delivery, s.closed = sealed, "done"
	s.notifyLocked()
	return nil
}

type receiverSide struct{ *relayPair }

func (s receiverSide) Answer(_ context.Context, answer Answer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed != "" {
		return &EndedError{Reason: s.closed}
	}
	if s.answer != nil {
		return errors.New("answered twice")
	}
	s.answer = &answer
	s.notifyLocked()
	return nil
}

func (s receiverSide) AwaitDelivery(ctx context.Context) ([]byte, error) {
	return waitFor(ctx, s.relayPair, func() ([]byte, bool) { return s.delivery, s.delivery != nil })
}

func party(words ...string) Party {
	return Party{Words: [2]string{words[0], words[1]}, SID: testSID, Origin: testOrigin}
}

// handOver runs both roles at once, the sender with its party and the
// receiver with its own.
func handOver(t *testing.T, relay *relayPair, sender, receiver Party) (sendErr error, link string, receiveErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	offer, err := NewOffer(sender)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() { sendErr = Send(ctx, senderSide{relay}, sender, offer, testLink) })
	wg.Go(func() { link, receiveErr = Receive(ctx, receiverSide{relay}, receiver, offer.Share) })
	wg.Wait()
	return sendErr, link, receiveErr
}

func TestHandsTheLinkToAReceiverWithTheSameWords(t *testing.T) {
	relay := newRelayPair()

	sendErr, link, receiveErr := handOver(t, relay, party("acid", "rocket"), party("acid", "rocket"))

	if sendErr != nil || receiveErr != nil {
		t.Fatalf("send: %v, receive: %v", sendErr, receiveErr)
	}
	if link != testLink {
		t.Errorf("received %q", link)
	}
	if relay.closedWith() != "done" {
		t.Errorf("closed with %q", relay.closedWith())
	}
}

func TestNeverDeliversWhenTheWordsDiffer(t *testing.T) {
	relay := newRelayPair()

	sendErr, _, receiveErr := handOver(t, relay, party("acid", "rocket"), party("acid", "robe"))

	if !errors.Is(sendErr, ErrCodeMismatch) || !errors.Is(receiveErr, ErrCodeMismatch) {
		t.Fatalf("send: %v, receive: %v", sendErr, receiveErr)
	}
	if relay.closedWith() != "mismatch" || relay.delivery != nil {
		t.Errorf("closed with %q, delivered %v", relay.closedWith(), relay.delivery != nil)
	}
}

func TestIsBoundToTheOrigin(t *testing.T) {
	other := party("acid", "rocket")
	other.Origin = "https://evil.example"

	sendErr, _, _ := handOver(t, newRelayPair(), party("acid", "rocket"), other)

	if !errors.Is(sendErr, ErrCodeMismatch) {
		t.Errorf("send: %v", sendErr)
	}
}

func TestIsBoundToTheSession(t *testing.T) {
	other := party("acid", "rocket")
	other.SID = randomBytes(SIDSize)

	sendErr, _, _ := handOver(t, newRelayPair(), party("acid", "rocket"), other)

	if !errors.Is(sendErr, ErrCodeMismatch) {
		t.Errorf("send: %v", sendErr)
	}
}

func TestRefusesAnOfferThatIsNoValidShare(t *testing.T) {
	relay := newRelayPair()

	_, err := Receive(context.Background(), receiverSide{relay}, party("acid", "rocket"), bytes.Repeat([]byte{0xff}, 32))

	if !errors.Is(err, ErrCodeMismatch) {
		t.Errorf("receive: %v", err)
	}
	if relay.closedWith() != "mismatch" {
		t.Errorf("closed with %q", relay.closedWith())
	}
}

func TestReportsATransferTheSenderCancelled(t *testing.T) {
	relay := newRelayPair()
	offer, err := NewOffer(party("acid", "rocket"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Receive(context.Background(), receiverSide{relay}, party("acid", "rocket"), offer.Share)
		done <- err
	}()

	// Cancel only once the receiver has answered and is waiting.
	if _, err := (senderSide{relay}).AwaitAnswer(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = relay.Close(context.Background(), Cancelled)

	ended, ok := errors.AsType[*EndedError](<-done)
	if !ok || ended.Reason != "cancelled" {
		t.Errorf("receive: %v", ended)
	}
}

func TestSendRefusesALinkTooLongBeforeWaiting(t *testing.T) {
	offer, err := NewOffer(party("acid", "rocket"))
	if err != nil {
		t.Fatal(err)
	}
	err = Send(context.Background(), senderSide{newRelayPair()}, party("acid", "rocket"), offer, strings.Repeat("x", MaxLinkSize+1))
	if !errors.Is(err, ErrLinkTooLong) {
		t.Errorf("send: %v", err)
	}
}

func TestSealedLink(t *testing.T) {
	keys, err := DeriveKeys(randomBytes(64), testSID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys.Confirm, keys.Payload) {
		t.Error("confirmation and payload keys are the same")
	}

	short, err := Seal(keys.Payload, testSID, "https://a.example/s#x")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(keys.Payload, testSID, testLink)
	if err != nil {
		t.Fatal(err)
	}
	if len(short) != SealedSize || len(sealed) != SealedSize {
		t.Errorf("sizes %d and %d, want %d", len(short), len(sealed), SealedSize)
	}
	if link, err := Open(keys.Payload, testSID, sealed); err != nil || link != testLink {
		t.Errorf("Open = %q, %v", link, err)
	}

	tampered := bytes.Clone(sealed)
	tampered[40] ^= 1
	for name, open := range map[string]func() (string, error){
		"tampered":      func() (string, error) { return Open(keys.Payload, testSID, tampered) },
		"other session": func() (string, error) { return Open(keys.Payload, make([]byte, SIDSize), sealed) },
		"wrong size":    func() (string, error) { return Open(keys.Payload, testSID, sealed[1:]) },
	} {
		if _, err := open(); !errors.Is(err, ErrCodeMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if _, err := Seal(keys.Payload, testSID, strings.Repeat("x", MaxLinkSize+1)); !errors.Is(err, ErrLinkTooLong) {
		t.Errorf("long link: %v", err)
	}
	if _, err := Seal(keys.Payload, testSID, strings.Repeat("x", MaxLinkSize)); err != nil {
		t.Errorf("longest link: %v", err)
	}
}
