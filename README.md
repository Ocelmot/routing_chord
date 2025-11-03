# Routing Chord

This crate sets up a peer to peer network using the chord protocol. It can route
data to an address through a series of aliases that wrap the data in layers of
encryption to provide anonymity.

This system allows data to flow in a single direction. A peer can send data to
some address. If the receiving peer is online and has established the required
aliases, it will be able to receive the sent data. To send data in the other
direction, the sender must establish its own address that it is listening to.

## Usage
First, create a state object for the chord to save its state and configuration
into. use one of the following to create the state.

```rust
	// Create a new state that will be saved at the provided filename
	let new_state = ChordSate::new("state.json");

	// Create a temp state that will not be saved
	let tmp_state = ChordSate::tmp();

	// Create a new state that will be loaded from, and later saved to the provided filename
	let loaded_state = ChordSate::load("state.json");
```

Second, host or join an existing network from the state.

```rust
	// Host a new network
	let hosted_handle = state.host();

	// Join an existing network
	// This will try to join previously seen peers that were saved to the state. (if any)
	// Then it will try to join using addresses from the provided Vec.
	let joined_handle = state.join(vec!["127.0.0.1:6200".into()]);

	// Attempts to join as above, but hosts a new network if no connections succeeded.
	let joined_or_hosted_handle = state.join_or_host(vec!["127.0.0.1:6200".into()]);
```

The network may take a moment to settle into its stable state after joining. To
start listening for incoming data, pass a ChordPublicKey to `listen_at()`. The
ChordPrivateKey can be saved and reused.  This provides a stable connection
address to which peers can connect.

```rust
let alias_id = ChordPrivateKey::generate(); // This is secret
let pub_key = alias_id.get_public_key(); // This is shared and saved by peers
let listen_handle = handle.listen_at(alias_id).await.expect("failed to establish a listen channel");

// Read data from the handle
let recvd_msg = listen_handle.recv().await.expect("should recv sent message");
```

Peers can send data via the corresponding ChordPublicKey.
```rust
let send_handle = handle_2.connect_to(pub_key);
send_handle.send(msg).await.expect("Failed to send through channel");
```

