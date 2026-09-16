package tsp_test

import (
	"context"
	"fmt"

	tsp "github.com/affinidi/affinidi-tsp-go"
)

func Example() {
	alice, _ := tsp.GenerateIdentity("did:example:alice", tsp.SigKeyEd25519, tsp.EncKeyX25519, nil)
	bob, _ := tsp.GenerateIdentity("did:example:bob", tsp.SigKeyEd25519, tsp.EncKeyX25519, nil)

	packed, err := tsp.Pack(alice, bob.Public(), &tsp.SCS{Data: []byte("hello world")}, nil)
	if err != nil {
		panic(err)
	}
	env, _ := tsp.Peek(packed.Message)
	fmt.Println(env.Sender, "->", env.Receiver, "confidential:", env.Confidential)

	msg, err := tsp.Open(bob, alice.Public(), packed.Message)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s %s\n", msg.Scheme, msg.Payload.(*tsp.SCS).Data)
	// Output:
	// did:example:alice -> did:example:bob confidential: true
	// hpke-base hello world
}

func ExampleEndpoint() {
	ctx := context.Background()
	alice, _ := tsp.GenerateIdentity("did:example:alice", tsp.SigKeyEd25519, tsp.EncKeyX25519, nil)
	bob, _ := tsp.GenerateIdentity("did:example:bob", tsp.SigKeyEd25519, tsp.EncKeyX25519, nil)

	knowsBob, _ := tsp.NewStaticResolver(bob.Public())
	knowsAlice, _ := tsp.NewStaticResolver(alice.Public())
	a, b := tsp.NewEndpoint(knowsBob), tsp.NewEndpoint(knowsAlice)
	_ = a.AddIdentity(alice)
	_ = b.AddIdentity(bob)

	invite, _ := a.Invite(ctx, alice.VID, bob.VID)
	ev, _ := b.Receive(ctx, invite.Message)
	fmt.Println(ev.Kind)

	accept, _ := b.Accept(ctx, bob.VID, alice.VID)
	ev, _ = a.Receive(ctx, accept.Message)
	fmt.Println(ev.Kind)

	hello, _ := a.Send(ctx, alice.VID, bob.VID, []byte("hi bob"))
	ev, _ = b.Receive(ctx, hello.Message)
	fmt.Println(ev.Kind, string(ev.Data))

	state, _ := b.State(ctx, bob.VID, alice.VID)
	fmt.Println(state.State)
	// Output:
	// invite
	// accept
	// message hi bob
	// bidirectional
}
