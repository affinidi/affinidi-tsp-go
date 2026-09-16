package tsp

import (
	"context"
	"errors"
	"io"
	"sync"
)

// Endpoint is a TSP endpoint: a set of VIDs it controls, a resolver for the
// VIDs of others, and a relationship store. It implements the direct
// relationship forming protocol (RFI / RFA / RFD) and gates application
// messages on it. It does no I/O: every operation returns or consumes encoded
// messages, so any transport can be layered on top.
//
// An Endpoint is safe for concurrent use.
type Endpoint struct {
	mu         sync.Mutex
	identities map[string]*PrivateIdentity
	resolver   VidResolver
	store      Store
	rand       io.Reader
}

// EndpointOption configures an Endpoint.
type EndpointOption func(*Endpoint)

// WithStore sets the relationship store (default: a new MemoryStore).
func WithStore(s Store) EndpointOption { return func(e *Endpoint) { e.store = s } }

// WithRand sets the randomness source (default: crypto/rand).
func WithRand(r io.Reader) EndpointOption { return func(e *Endpoint) { e.rand = r } }

// NewEndpoint creates an endpoint that resolves peers with resolver.
func NewEndpoint(resolver VidResolver, opts ...EndpointOption) *Endpoint {
	e := &Endpoint{identities: make(map[string]*PrivateIdentity), resolver: resolver}
	for _, o := range opts {
		o(e)
	}
	if e.store == nil {
		e.store = NewMemoryStore()
	}
	return e
}

// AddIdentity registers a VID this endpoint controls.
func (e *Endpoint) AddIdentity(id *PrivateIdentity) error {
	if err := id.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := *id
	e.identities[id.VID] = &cp
	return nil
}

func (e *Endpoint) local(vid string) (*PrivateIdentity, error) {
	id, ok := e.identities[vid]
	if !ok {
		return nil, newErr(KindInvalidInput, "%q is not a VID of this endpoint", vid)
	}
	return id, nil
}

func (e *Endpoint) remote(ctx context.Context, vid string) (*Identity, error) {
	if e.resolver == nil {
		return nil, newErr(KindSender, "no resolver for %q", vid)
	}
	id, err := e.resolver.Resolve(ctx, vid)
	if err != nil {
		return nil, wrapErr(KindSender, err, "resolving %q", vid)
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if id.VID != vid {
		return nil, newErr(KindSender, "resolver returned %q for %q", id.VID, vid)
	}
	return id, nil
}

func (e *Endpoint) pack(ctx context.Context, from, to string, p Payload) (*Packed, error) {
	sender, err := e.local(from)
	if err != nil {
		return nil, err
	}
	receiver, err := e.remote(ctx, to)
	if err != nil {
		if KindOf(err) == KindSender {
			return nil, &Error{Kind: KindInvalidInput, Msg: "unknown peer", Err: err}
		}
		return nil, err
	}
	return Pack(sender, receiver, p, &PackOptions{Rand: e.rand})
}

func (e *Endpoint) relationship(ctx context.Context, local, remote string) (Relationship, error) {
	r, err := e.store.Relationship(ctx, local, remote)
	if err != nil {
		return Relationship{}, wrapErr(KindInternal, err, "reading relationship")
	}
	return r, nil
}

func (e *Endpoint) setRelationship(ctx context.Context, local, remote string, r Relationship) error {
	var err error
	if r.State == StateNone {
		err = e.store.DeleteRelationship(ctx, local, remote)
	} else {
		err = e.store.SetRelationship(ctx, local, remote, r)
	}
	if err != nil {
		return wrapErr(KindInternal, err, "storing relationship")
	}
	return nil
}

// State returns the relationship between a local and a remote VID.
func (e *Endpoint) State(ctx context.Context, local, remote string) (Relationship, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.relationship(ctx, local, remote)
}

// Invite sends a relationship forming invite from a local VID to a remote one.
// It is refused while an invite from the remote is pending (accept it instead)
// or once the relationship is established. Re-inviting while an invite is
// outstanding replaces it.
func (e *Endpoint) Invite(ctx context.Context, from, to string) (*Packed, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.relationship(ctx, from, to)
	if err != nil {
		return nil, err
	}
	if r.State != StateNone && r.State != StateInviteSent {
		return nil, newErr(KindRelationship, "cannot invite: relationship is %v", r.State)
	}
	packed, err := e.pack(ctx, from, to, &RFI{ReplyPath: []string{}})
	if err != nil {
		return nil, err
	}
	d := *packed.Digest
	return packed, e.setRelationship(ctx, from, to, Relationship{State: StateInviteSent, Digest: &d, Initiator: true})
}

// Accept answers the invite received from remote VID to, from local VID from.
func (e *Endpoint) Accept(ctx context.Context, from, to string) (*Packed, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.relationship(ctx, from, to)
	if err != nil {
		return nil, err
	}
	if r.State != StateInviteReceived || r.Digest == nil {
		return nil, newErr(KindRelationship, "no invite from %q to accept (relationship is %v)", to, r.State)
	}
	packed, err := e.pack(ctx, from, to, &RFA{InviteDigest: *r.Digest})
	if err != nil {
		return nil, err
	}
	reply := *packed.Digest
	r.State, r.ReplyDigest, r.Initiator = StateBidirectional, &reply, false
	return packed, e.setRelationship(ctx, from, to, r)
}

// Cancel declines a pending invite, withdraws one we sent, or cancels an
// established relationship, and forgets the relationship locally.
//
// The RFD names the relationship by a digest the remote holds: for an
// established relationship, the digest this side received (the Reply_Digest
// for the inviter, the Digest for the accepter); for a pending invite, that
// invite's Digest.
func (e *Endpoint) Cancel(ctx context.Context, from, to string) (*Packed, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.relationship(ctx, from, to)
	if err != nil {
		return nil, err
	}
	if r.State == StateNone || r.Digest == nil {
		return nil, newErr(KindRelationship, "no relationship with %q to cancel", to)
	}
	d := *r.Digest
	if r.State == StateBidirectional && r.Initiator && r.ReplyDigest != nil {
		d = *r.ReplyDigest
	}
	packed, err := e.pack(ctx, from, to, &RFD{Digest: d})
	if err != nil {
		return nil, err
	}
	return packed, e.setRelationship(ctx, from, to, Relationship{})
}

// Send packs application data over an established relationship.
func (e *Endpoint) Send(ctx context.Context, from, to string, data []byte) (*Packed, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.relationship(ctx, from, to)
	if err != nil {
		return nil, err
	}
	if r.State != StateBidirectional {
		return nil, newErr(KindRelationship, "cannot send: relationship with %q is %v", to, r.State)
	}
	if data == nil {
		data = []byte{}
	}
	return e.pack(ctx, from, to, &SCS{Data: data})
}

// EventKind classifies a received message.
type EventKind uint8

// Event kinds.
const (
	EventInvite  EventKind = iota + 1 // an RFI
	EventAccept                       // an RFA answering our invite
	EventCancel                       // an RFD
	EventMessage                      // application data (XSCS)
	EventControl                      // generic control payload (XCTL)
	EventPadding                      // a padding message (XPAD)
	EventHop                          // a nested or routed message (XHOP), inner unopened
)

func (k EventKind) String() string {
	switch k {
	case EventInvite:
		return "invite"
	case EventAccept:
		return "accept"
	case EventCancel:
		return "cancel"
	case EventMessage:
		return "message"
	case EventControl:
		return "control"
	case EventPadding:
		return "padding"
	case EventHop:
		return "hop"
	}
	return "unknown"
}

// Event is the outcome of receiving a message.
type Event struct {
	Kind EventKind
	// From is the remote (envelope sender) VID, To the local VID.
	From, To string
	// Data is the application data of an EventMessage or EventControl.
	Data []byte
	// Digest is the invite digest (invite, accept) or the named digest (cancel).
	Digest *Digest
	// ReplyDigest is the accept's own digest.
	ReplyDigest *Digest
	// Message is the opened message.
	Message *Message
}

// Receive opens a message addressed to one of this endpoint's VIDs and applies
// it to the relationship state.
//
// Relationship rules: an invite crossing our own outstanding invite for the
// same pair is kept only if its digest is lower (binary comparison), otherwise
// it is refused; an accept must echo the digest of our outstanding invite; a
// cancel must name a digest of an existing relationship; application data is
// accepted only over a bidirectional relationship. A refused message is an
// error of kind KindRelationship and leaves the state unchanged.
func (e *Endpoint) Receive(ctx context.Context, msg []byte) (*Event, error) {
	env, err := Peek(msg)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	local, ok := e.identities[env.Receiver]
	if !ok {
		return nil, newErr(KindReceiver, "message is addressed to %q, which is not a VID of this endpoint", env.Receiver)
	}
	remote, err := e.remote(ctx, env.Sender)
	if err != nil {
		return nil, err
	}
	m, err := Open(local, remote, msg)
	if err != nil {
		return nil, err
	}
	ev := &Event{From: m.Sender, To: local.VID, Message: m}
	r, err := e.relationship(ctx, ev.To, ev.From)
	if err != nil {
		return nil, err
	}

	switch p := m.Payload.(type) {
	case *RFI:
		ev.Kind = EventInvite
		d := p.Digest
		ev.Digest = &d
		switch r.State {
		case StateNone, StateInviteReceived:
			// A fresh invite supersedes an unanswered one.
		case StateInviteSent:
			// Crossing invites: both sides keep the lower digest.
			if r.Digest != nil && r.Digest.Compare(d) <= 0 {
				return nil, newErr(KindRelationship, "crossing invite discarded: our outstanding invite has the lower digest")
			}
		default:
			return nil, newErr(KindRelationship, "invite for an established relationship")
		}
		return ev, e.setRelationship(ctx, ev.To, ev.From, Relationship{State: StateInviteReceived, Digest: &d})
	case *RFA:
		ev.Kind = EventAccept
		inv, reply := p.InviteDigest, p.ReplyDigest
		ev.Digest, ev.ReplyDigest = &inv, &reply
		if r.State != StateInviteSent || r.Digest == nil || !r.Digest.Equal(inv) {
			return nil, newErr(KindRelationship, "accept does not answer an outstanding invite")
		}
		r.State, r.ReplyDigest = StateBidirectional, &reply
		return ev, e.setRelationship(ctx, ev.To, ev.From, r)
	case *RFD:
		ev.Kind = EventCancel
		d := p.Digest
		ev.Digest = &d
		known := (r.Digest != nil && r.Digest.Equal(d)) || (r.ReplyDigest != nil && r.ReplyDigest.Equal(d))
		if r.State == StateNone || !known {
			return nil, newErr(KindRelationship, "cancel names no relationship we hold")
		}
		return ev, e.setRelationship(ctx, ev.To, ev.From, Relationship{})
	case *SCS, *CTL:
		if r.State != StateBidirectional {
			return nil, newErr(KindRelationship, "application message from %q without a relationship", ev.From)
		}
		if s, ok := p.(*SCS); ok {
			ev.Kind, ev.Data = EventMessage, s.Data
		} else {
			ev.Kind, ev.Data = EventControl, p.(*CTL).Data
		}
		return ev, nil
	case *PAD:
		ev.Kind = EventPadding
		return ev, nil
	case *HOP:
		if r.State != StateBidirectional {
			return nil, newErr(KindRelationship, "nested or routed message from %q without a relationship", ev.From)
		}
		ev.Kind = EventHop
		return ev, nil
	}
	return nil, errors.New("tsp: unreachable payload type")
}
