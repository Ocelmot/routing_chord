use std::time::Duration;

use routing_chord::ChordState;

use tokio::time::sleep;

#[tokio::test]
#[test_log::test]
async fn disconnected_query_predecessor() {
    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6100");
    let mut handle_1 = chord_state_1.host().expect("host should start");

    // wait for things to settle
    sleep(Duration::from_secs(5)).await;

    // check node 1's predecessor
    let node_1_pred  = handle_1.predecessor().await.expect("node should be running");
    assert!(node_1_pred.is_none(), "node should not be connected to any other node");
}

#[tokio::test]
#[test_log::test]
async fn disconnected_query_successor() {
    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6101");
    let mut handle_1 = chord_state_1.host().expect("host should start");

    // wait for things to settle
    sleep(Duration::from_secs(5)).await;

    // check node 1's successor
    let node_1_successor  = handle_1.successor().await.expect("node should be running");
    assert!(node_1_successor.is_none(), "node should not be connected to any other node");
}
