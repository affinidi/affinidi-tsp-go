package tsp

import (
	"context"
	"testing"
)

type testNet struct {
	alice, bob     *PrivateIdentity
	epAlice, epBob *Endpoint
	ctx            context.Context
}

func newTestNet(t *testing.T) *testNet {
	t.Helper()
	alice, bob := classicPair(t)
	ra, err := NewStaticResolver(bob.Public())
	if err != nil {
		t.Fatal(err)
	}
	rb, err := NewStaticResolver(alice.Public())
	if err != nil {
		t.Fatal(err)
	}
	n := &testNet{alice: alice, bob: bob, epAlice: NewEndpoint(ra), epBob: NewEndpoint(rb), ctx: context.Background()}
	if err := n.epAlice.AddIdentity(alice); err != nil {
		t.Fatal(err)
	}
	if err := n.epBob.AddIdentity(bob); err != nil {
		t.Fatal(err)
	}
	return n
}

func (n *testNet) state(t *testing.T, ep *Endpoint, local, remote string) Relationship {
	t.Helper()
	r, err := ep.State(n.ctx, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// must panics on error; a panic fails the running test with the error.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestEndpointRelationshipLifecycle(t *testing.T) {
	n := newTestNet(t)
	a, b := n.alice.VID, n.bob.VID

	// No relationship: sending is refused, and so is receiving.
	_, err := n.epAlice.Send(n.ctx, a, b, []byte("hi"))
	expectKind(t, err, KindRelationship)
	stray, err := Pack(n.alice, n.bob.Public(), &SCS{Data: []byte("hi")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.epBob.Receive(n.ctx, stray.Message)
	expectKind(t, err, KindRelationship)

	invite := must(n.epAlice.Invite(n.ctx, a, b))
	if s := n.state(t, n.epAlice, a, b); s.State != StateInviteSent || !s.Digest.Equal(*invite.Digest) {
		t.Fatalf("alice: %+v", s)
	}
	ev := must(n.epBob.Receive(n.ctx, invite.Message))
	if ev.Kind != EventInvite || ev.From != a || ev.To != b || !ev.Digest.Equal(*invite.Digest) {
		t.Fatalf("bob event: %+v", ev)
	}
	if s := n.state(t, n.epBob, b, a); s.State != StateInviteReceived {
		t.Fatalf("bob: %+v", s)
	}
	_, err = n.epBob.Send(n.ctx, b, a, []byte("too early"))
	expectKind(t, err, KindRelationship)

	accept := must(n.epBob.Accept(n.ctx, b, a))
	ev = must(n.epAlice.Receive(n.ctx, accept.Message))
	if ev.Kind != EventAccept || !ev.Digest.Equal(*invite.Digest) || !ev.ReplyDigest.Equal(*accept.Digest) {
		t.Fatalf("alice event: %+v", ev)
	}
	for _, s := range []Relationship{n.state(t, n.epAlice, a, b), n.state(t, n.epBob, b, a)} {
		if s.State != StateBidirectional || !s.Digest.Equal(*invite.Digest) || !s.ReplyDigest.Equal(*accept.Digest) {
			t.Fatalf("not bidirectional: %+v", s)
		}
	}
	// Replaying the accept is refused.
	_, err = n.epAlice.Receive(n.ctx, accept.Message)
	expectKind(t, err, KindRelationship)

	msg := must(n.epAlice.Send(n.ctx, a, b, []byte("hello")))
	ev = must(n.epBob.Receive(n.ctx, msg.Message))
	if ev.Kind != EventMessage || string(ev.Data) != "hello" {
		t.Fatalf("message event: %+v", ev)
	}
	reply := must(n.epBob.Send(n.ctx, b, a, []byte("hi alice")))
	if ev = must(n.epAlice.Receive(n.ctx, reply.Message)); string(ev.Data) != "hi alice" {
		t.Fatal("reply")
	}

	cancel := must(n.epBob.Cancel(n.ctx, b, a))
	ev = must(n.epAlice.Receive(n.ctx, cancel.Message))
	if ev.Kind != EventCancel || !ev.Digest.Equal(*invite.Digest) {
		t.Fatalf("cancel event: %+v", ev)
	}
	if n.state(t, n.epAlice, a, b).State != StateNone || n.state(t, n.epBob, b, a).State != StateNone {
		t.Fatal("cancel did not clear the relationship")
	}
	_, err = n.epBob.Receive(n.ctx, msg.Message)
	expectKind(t, err, KindRelationship)
	_, err = n.epAlice.Receive(n.ctx, cancel.Message)
	expectKind(t, err, KindRelationship)
}

func TestEndpointInviterCancelNamesReplyDigest(t *testing.T) {
	n := newTestNet(t)
	a, b := n.alice.VID, n.bob.VID
	invite := must(n.epAlice.Invite(n.ctx, a, b))
	must(n.epBob.Receive(n.ctx, invite.Message))
	accept := must(n.epBob.Accept(n.ctx, b, a))
	must(n.epAlice.Receive(n.ctx, accept.Message))
	cancel := must(n.epAlice.Cancel(n.ctx, a, b))
	ev := must(n.epBob.Receive(n.ctx, cancel.Message))
	if !ev.Digest.Equal(*accept.Digest) {
		t.Fatal("inviter's cancel should name the Reply_Digest it received")
	}
}

func TestEndpointAcceptMustMatchInvite(t *testing.T) {
	n := newTestNet(t)
	a, b := n.alice.VID, n.bob.VID
	must(n.epAlice.Invite(n.ctx, a, b))
	// An accept of an invite alice never sent.
	forged, err := Pack(n.bob, n.alice.Public(), &RFA{InviteDigest: Digest{Alg: DigestSHA2256, Value: [32]byte{1}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.epAlice.Receive(n.ctx, forged.Message)
	expectKind(t, err, KindRelationship)
	if n.state(t, n.epAlice, a, b).State != StateInviteSent {
		t.Fatal("state changed on a refused accept")
	}
	_, err = n.epBob.Accept(n.ctx, b, a)
	expectKind(t, err, KindRelationship)
}

func TestEndpointDeclineInvite(t *testing.T) {
	n := newTestNet(t)
	a, b := n.alice.VID, n.bob.VID
	invite := must(n.epAlice.Invite(n.ctx, a, b))
	must(n.epBob.Receive(n.ctx, invite.Message))
	decline := must(n.epBob.Cancel(n.ctx, b, a))
	ev := must(n.epAlice.Receive(n.ctx, decline.Message))
	if ev.Kind != EventCancel || n.state(t, n.epAlice, a, b).State != StateNone {
		t.Fatal("decline")
	}
}

func TestEndpointInviteRace(t *testing.T) {
	for i := 0; i < 8; i++ {
		n := newTestNet(t)
		a, b := n.alice.VID, n.bob.VID
		ia := must(n.epAlice.Invite(n.ctx, a, b))
		ib := must(n.epBob.Invite(n.ctx, b, a))

		_, errA := n.epAlice.Receive(n.ctx, ib.Message)
		_, errB := n.epBob.Receive(n.ctx, ia.Message)
		aLower := ia.Digest.Compare(*ib.Digest) < 0

		// Exactly one side discards the incoming invite: the one whose own
		// invite has the lower digest.
		if aLower {
			expectKind(t, errA, KindRelationship)
			if errB != nil {
				t.Fatal(errB)
			}
			accept := must(n.epBob.Accept(n.ctx, b, a))
			must(n.epAlice.Receive(n.ctx, accept.Message))
		} else {
			expectKind(t, errB, KindRelationship)
			if errA != nil {
				t.Fatal(errA)
			}
			accept := must(n.epAlice.Accept(n.ctx, a, b))
			must(n.epBob.Receive(n.ctx, accept.Message))
		}
		sa, sb := n.state(t, n.epAlice, a, b), n.state(t, n.epBob, b, a)
		if sa.State != StateBidirectional || sb.State != StateBidirectional || !sa.Digest.Equal(*sb.Digest) {
			t.Fatalf("race did not converge: %+v %+v", sa, sb)
		}
		kept := ia.Digest
		if !aLower {
			kept = ib.Digest
		}
		if !sa.Digest.Equal(*kept) {
			t.Fatal("the higher digest was kept")
		}
	}
}

func TestEndpointReceiverAndSenderChecks(t *testing.T) {
	n := newTestNet(t)
	carol := genID(t, "did:example:carol", SigKeyEd25519, EncKeyX25519)
	toCarol, err := Pack(n.alice, carol.Public(), &RFI{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.epBob.Receive(n.ctx, toCarol.Message)
	expectKind(t, err, KindReceiver)

	fromCarol, err := Pack(carol, n.bob.Public(), &RFI{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.epBob.Receive(n.ctx, fromCarol.Message)
	expectKind(t, err, KindSender)
}
