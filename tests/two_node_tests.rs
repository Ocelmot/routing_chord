use std::time::Duration;

use routing_chord::{id::ChordPrivateKey, ChordState};

use tokio::time::sleep;

use tracing::trace;

static TESTING_STABILIZE_INTERVAL: Duration = Duration::from_secs(5);
static TESTING_FIX_FINGERS_INTERVAL: Duration = Duration::from_secs(5);

#[tokio::test]
#[test_log::test]
async fn two_nodes_query_predecessor() {
    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6200");
    let mut handle_1 = chord_state_1.host().expect("host should start");

    let mut chord_state_2 = ChordState::temp();
    chord_state_2.set_listen_addr("127.0.0.1:6201");
    let mut handle_2 = chord_state_2
        .join(vec!["127.0.0.1:6200".into()])
        .await
        .expect("join should succeed since host is listening");

    // wait for things to settle
    sleep(Duration::from_secs(5)).await;

    // check node 1's predecessor
    let node_1_pred  = handle_1.predecessor().await.expect("node should be running");
    let node_1_pred = node_1_pred.expect("node should connect to each other");
    assert_eq!(handle_2.get_key(), &node_1_pred, "node 1's predecessor is not the id of node 2");

    // check node 2's predecessor
    let node_2_pred  = handle_2.predecessor().await.expect("node should be running");
    let node_2_pred = node_2_pred.expect("node should connect to each other");
    assert_eq!(handle_1.get_key(), &node_2_pred, "node 2's predecessor is not the id of node 1");
}

#[tokio::test]
#[test_log::test]
async fn two_nodes_query_successor() {
    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6210");
    let mut handle_1 = chord_state_1.host().expect("host should start");

    let mut chord_state_2 = ChordState::temp();
    chord_state_2.set_listen_addr("127.0.0.1:6211");
    let mut handle_2 = chord_state_2
        .join(vec!["127.0.0.1:6210".into()])
        .await
        .expect("join should succeed since host is listening");

    // wait for things to settle
    sleep(Duration::from_secs(5)).await;

    // check node 1's successor
    let node_1_successor  = handle_1.successor().await.expect("node should be running");
    let node_1_successor = node_1_successor.expect("node should connect to each other");
    assert_eq!(handle_2.get_key(), &node_1_successor, "node 1's successor is not the id of node 2");

    // check node 2's successor
    let node_2_successor  = handle_2.successor().await.expect("node should be running");
    let node_2_successor = node_2_successor.expect("node should connect to each other");
    assert_eq!(handle_1.get_key(), &node_2_successor, "node 2's successor is not the id of node 1");
}

#[tokio::test]
#[test_log::test]
async fn two_nodes_establish_alias() {
    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6220");
    chord_state_1.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    chord_state_1.set_fix_fingers_interval(TESTING_FIX_FINGERS_INTERVAL);
    let mut handle_1 = chord_state_1.host().expect("host should start");

    let mut chord_state_2 = ChordState::temp();
    chord_state_2.set_listen_addr("127.0.0.1:6221");
    chord_state_2.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    chord_state_2.set_fix_fingers_interval(TESTING_FIX_FINGERS_INTERVAL);
    let mut handle_2 = chord_state_2
        .join(vec!["127.0.0.1:6220".into()])
        .await
        .expect("join should succeed since host is listening");

    // wait for things to settle
    sleep(Duration::from_secs(10)).await;

    // show state
    handle_1.debug().await.unwrap();
    handle_2.debug().await.unwrap();

    // check node 1's successor
    let node_1_successor  = handle_1.successor().await.expect("node should be running");
    let node_1_successor = node_1_successor.expect("node should connect to each other");
    assert_eq!(handle_2.get_key(), &node_1_successor, "node 1's successor is not the id of node 2");

    // check node 2's successor
    let node_2_successor  = handle_2.successor().await.expect("node should be running");
    let node_2_successor = node_2_successor.expect("node should connect to each other");
    assert_eq!(handle_1.get_key(), &node_2_successor, "node 2's successor is not the id of node 1");

    // establish alias
    let alias_id = ChordPrivateKey::generate();
    let pub_key = alias_id.get_public_key();
    let mut listen_handle = handle_1.listen_at(alias_id).await.expect("failed to establish a listen channel");

    // wait for things to settle
    sleep(Duration::from_secs(25)).await;
    trace!("----- Sending test message -----");

    let msg = String::from("Test Message!").as_bytes().to_vec();
    // handle_2.connect_to(pub_key, msg.clone()).await.expect("failed to connect to channel");
    let send_handle = handle_2.connect_to(pub_key);
    send_handle.send(msg.clone()).await.expect("Failed to send through channel");

    let recvd_msg = listen_handle.recv().await.expect("should recv sent message");
    assert_eq!(msg, recvd_msg, "recvd_msg should be equal to the sent message");

    sleep(Duration::from_secs(5)).await;
}