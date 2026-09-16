package tsp

import (
	"context"
	"errors"
	"sync"
)

// VidResolver resolves a VID to its current public Identity. Implementations
// perform whatever verification the VID type requires (DID resolution, KERI
// key state, ...). A resolver must be safe for concurrent use.
type VidResolver interface {
	Resolve(ctx context.Context, vid string) (*Identity, error)
}

// ErrNotFound is returned by resolvers and stores for an unknown VID or
// relationship.
var ErrNotFound = errors.New("tsp: not found")

// StaticResolver resolves VIDs from an in-memory table. It suits tests,
// out-of-band introductions and self-certifying VIDs whose keys are known.
type StaticResolver struct {
	mu  sync.RWMutex
	ids map[string]*Identity
}

// NewStaticResolver returns a resolver holding the given identities.
func NewStaticResolver(ids ...*Identity) (*StaticResolver, error) {
	r := &StaticResolver{ids: make(map[string]*Identity)}
	for _, id := range ids {
		if err := r.Add(id); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Add registers (or replaces) an identity.
func (r *StaticResolver) Add(id *Identity) error {
	if err := id.Validate(); err != nil {
		return err
	}
	cp := *id
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ids == nil {
		r.ids = make(map[string]*Identity)
	}
	r.ids[id.VID] = &cp
	return nil
}

// Resolve implements VidResolver.
func (r *StaticResolver) Resolve(_ context.Context, vid string) (*Identity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.ids[vid]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *id
	return &cp, nil
}

// RelationshipState is the state of the relationship between a local and a
// remote VID.
type RelationshipState uint8

// Relationship states.
const (
	// StateNone: no relationship.
	StateNone RelationshipState = iota
	// StateInviteSent: we sent an RFI and await the RFA.
	StateInviteSent
	// StateInviteReceived: we received an RFI and have not answered it.
	StateInviteReceived
	// StateBidirectional: the RFI/RFA exchange completed.
	StateBidirectional
)

func (s RelationshipState) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateInviteSent:
		return "invite-sent"
	case StateInviteReceived:
		return "invite-received"
	case StateBidirectional:
		return "bidirectional"
	}
	return "unknown"
}

// Relationship is the stored state of <local, remote>.
type Relationship struct {
	State RelationshipState
	// Digest is the invite's Digest, which identifies the inviter's direction
	// of the relationship (and is the thread identifier).
	Digest *Digest
	// ReplyDigest is the accept's Reply_Digest, identifying the accepter's
	// direction. Set once bidirectional.
	ReplyDigest *Digest
	// Initiator reports whether the local VID sent the invite.
	Initiator bool
}

// Store persists relationships. Implementations must be safe for concurrent
// use; the Endpoint serialises its own read-modify-write sequences.
type Store interface {
	// Relationship returns the relationship, or a zero Relationship (StateNone)
	// if there is none.
	Relationship(ctx context.Context, local, remote string) (Relationship, error)
	// SetRelationship stores the relationship.
	SetRelationship(ctx context.Context, local, remote string, r Relationship) error
	// DeleteRelationship removes the relationship if it exists.
	DeleteRelationship(ctx context.Context, local, remote string) error
}

type relKey struct{ local, remote string }

// MemoryStore is an in-memory Store.
type MemoryStore struct {
	mu   sync.RWMutex
	rels map[relKey]Relationship
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rels: make(map[relKey]Relationship)}
}

// Relationship implements Store.
func (s *MemoryStore) Relationship(_ context.Context, local, remote string) (Relationship, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rels[relKey{local, remote}], nil
}

// SetRelationship implements Store.
func (s *MemoryStore) SetRelationship(_ context.Context, local, remote string, r Relationship) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rels == nil {
		s.rels = make(map[relKey]Relationship)
	}
	if r.State == StateNone {
		delete(s.rels, relKey{local, remote})
		return nil
	}
	s.rels[relKey{local, remote}] = r
	return nil
}

// DeleteRelationship implements Store.
func (s *MemoryStore) DeleteRelationship(_ context.Context, local, remote string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rels, relKey{local, remote})
	return nil
}
