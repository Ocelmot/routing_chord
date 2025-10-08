use std::time::Duration;

use routing_chord::ChordState;

use tokio::time::sleep;

use tracing::debug;
use tracing_test::traced_test;

static TESTING_STABILIZE_INTERVAL: Duration = Duration::from_secs(5);

#[tokio::test]
#[traced_test]
async fn three_nodes_proper_order() {
    let mut handles = Vec::new();

    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6300");
    chord_state_1.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_1.host().expect("host should start"));

    let mut chord_state_2 = ChordState::temp();
    chord_state_2.set_listen_addr("127.0.0.1:6301");
    chord_state_2.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_2
        .join(vec!["127.0.0.1:6300".into()])
        .await
        .expect("join should succeed since host is listening"));

    let mut chord_state_3 = ChordState::temp();
    chord_state_3.set_listen_addr("127.0.0.1:6302");
    chord_state_3.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_3
        .join(vec!["127.0.0.1:6300".into()])
        .await
        .expect("join should succeed since host is listening"));

    handles.sort_by(|a, b|{
        a.get_key().cmp(b.get_key())
    });

    // wait for things to settle
    debug!("Waiting for system to settle...");
    sleep(Duration::from_secs(10)).await;
    debug!("Wait completed");

    // show state
    handles[0].debug().await.unwrap();
    handles[1].debug().await.unwrap();
    handles[2].debug().await.unwrap();

    let pred_0 = handles[0].predecessor().await.expect("node should be running");
    let pred_0 = pred_0.expect("nodes should all be connected");
    let suc_0 = handles[0].successor().await.expect("node should be running");
    let suc_0 = suc_0.expect("nodes should all be connected");
    
    let pred_1 = handles[1].predecessor().await.expect("node should be running");
    let pred_1 = pred_1.expect("nodes should all be connected");
    let suc_1 = handles[1].successor().await.expect("node should be running");
    let suc_1 = suc_1.expect("nodes should all be connected");
    
    let pred_2 = handles[2].predecessor().await.expect("node should be running");
    let pred_2 = pred_2.expect("nodes should all be connected");    
    let suc_2 = handles[2].successor().await.expect("node should be running");
    let suc_2 = suc_2.expect("nodes should all be connected");

    // Verify order
    // Verify predecessors
    assert_eq!(&pred_0, handles[2].get_key(), "node 0's predecessor is not the id of node 2 ");
    println!("pred(0) {:?} == n2 {:?}", pred_0.get_location(), handles[2].get_key().get_location());
    assert_eq!(&pred_1, handles[0].get_key(), "node 1's predecessor is not the id of node 0 ");
    println!("pred(n1) {:?} == n0 {:?}", pred_1.get_location(), handles[0].get_key().get_location());
    assert_eq!(&pred_2, handles[1].get_key(), "node 2's predecessor is not the id of node 1 ");
    println!("pred(n2) {:?} == n1 {:?}", pred_2.get_location(), handles[1].get_key().get_location());
    // Verify successors
    println!("suc(n0) {:?} == n1 {:?}", suc_0.get_location(), handles[1].get_key().get_location());
    assert_eq!(&suc_0, handles[1].get_key(), "node 0's successor is not the id of node 1 ");
    println!("suc(n1) {:?} == n2 {:?}", suc_1.get_location(), handles[2].get_key().get_location());
    assert_eq!(&suc_1, handles[2].get_key(), "node 1's successor is not the id of node 2 ");
    println!("suc(n2) {:?} == n0 {:?}", suc_2.get_location(), handles[0].get_key().get_location());
    assert_eq!(&suc_2, handles[0].get_key(), "node 2's successor is not the id of node 0 ");
}

#[tokio::test]
#[traced_test]
async fn three_nodes_query_predecessor_of() {
    let mut handles = Vec::new();

    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6310");
    chord_state_1.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_1.host().expect("host should start"));

    let mut chord_state_2 = ChordState::temp();
    chord_state_2.set_listen_addr("127.0.0.1:6311");
    chord_state_2.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_2
        .join(vec!["127.0.0.1:6310".into()])
        .await
        .expect("join should succeed since host is listening"));

    let mut chord_state_3 = ChordState::temp();
    chord_state_3.set_listen_addr("127.0.0.1:6312");
    chord_state_3.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_3
        .join(vec!["127.0.0.1:6310".into()])
        .await
        .expect("join should succeed since host is listening"));

    handles.sort_by(|a, b|{
        a.get_key().cmp(b.get_key())
    });

    // wait for things to settle
    debug!("Waiting for system to settle...");
    sleep(Duration::from_secs(10)).await;
    debug!("Wait completed");

    // show state
    handles[0].debug().await.unwrap();
    handles[1].debug().await.unwrap();
    handles[2].debug().await.unwrap();

    let pred_0 = handles[0].predecessor().await.expect("node should be running");
    let pred_0 = pred_0.expect("nodes should all be connected");
    let suc_0 = handles[0].successor().await.expect("node should be running");
    let suc_0 = suc_0.expect("nodes should all be connected");
    
    let pred_1 = handles[1].predecessor().await.expect("node should be running");
    let pred_1 = pred_1.expect("nodes should all be connected");
    let suc_1 = handles[1].successor().await.expect("node should be running");
    let suc_1 = suc_1.expect("nodes should all be connected");
    
    let pred_2 = handles[2].predecessor().await.expect("node should be running");
    let pred_2 = pred_2.expect("nodes should all be connected");    
    let suc_2 = handles[2].successor().await.expect("node should be running");
    let suc_2 = suc_2.expect("nodes should all be connected");

    // Verify order
    // Verify predecessors
    assert_eq!(&pred_0, handles[2].get_key(), "node 0's predecessor is not the id of node 2 ");
    println!("pred(0) {:?} == n2 {:?}", pred_0.get_location(), handles[2].get_key().get_location());
    assert_eq!(&pred_1, handles[0].get_key(), "node 1's predecessor is not the id of node 0 ");
    println!("pred(n1) {:?} == n0 {:?}", pred_1.get_location(), handles[0].get_key().get_location());
    assert_eq!(&pred_2, handles[1].get_key(), "node 2's predecessor is not the id of node 1 ");
    println!("pred(n2) {:?} == n1 {:?}", pred_2.get_location(), handles[1].get_key().get_location());
    // Verify successors
    println!("suc(n0) {:?} == n1 {:?}", suc_0.get_location(), handles[1].get_key().get_location());
    assert_eq!(&suc_0, handles[1].get_key(), "node 0's successor is not the id of node 1 ");
    println!("suc(n1) {:?} == n2 {:?}", suc_1.get_location(), handles[2].get_key().get_location());
    assert_eq!(&suc_1, handles[2].get_key(), "node 1's successor is not the id of node 2 ");
    println!("suc(n2) {:?} == n0 {:?}", suc_2.get_location(), handles[0].get_key().get_location());
    assert_eq!(&suc_2, handles[0].get_key(), "node 2's successor is not the id of node 0 ");

    // use 2 to request the predecessor of 1, should return id of 0
    let key_1 = handles[1].get_key().clone();
    let pred_of_1 = handles[2].get_predecessor(&key_1).await.expect("should not time out");
    println!("pred_of_1, {:?}", pred_of_1.sha256());
    assert_eq!(&pred_of_1, handles[1].get_key(), "failed to get correct predecessor key");
}

#[tokio::test]
#[traced_test]
async fn three_nodes_query_successor_of() {
    let mut handles = Vec::new();

    let mut chord_state_1 = ChordState::temp();
    chord_state_1.set_listen_addr("127.0.0.1:6320");
    chord_state_1.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_1.host().expect("host should start"));

    let mut chord_state_2 = ChordState::temp();
    chord_state_2.set_listen_addr("127.0.0.1:6321");
    chord_state_2.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_2
        .join(vec!["127.0.0.1:6320".into()])
        .await
        .expect("join should succeed since host is listening"));

    let mut chord_state_3 = ChordState::temp();
    chord_state_3.set_listen_addr("127.0.0.1:6322");
    chord_state_3.set_stabilize_interval(TESTING_STABILIZE_INTERVAL);
    handles.push(chord_state_3
        .join(vec!["127.0.0.1:6320".into()])
        .await
        .expect("join should succeed since host is listening"));

    handles.sort_by(|a, b|{
        a.get_key().cmp(b.get_key())
    });

    // wait for things to settle
    debug!("Waiting for system to settle...");
    sleep(Duration::from_secs(10)).await;
    debug!("Wait completed");

    // show state
    handles[0].debug().await.unwrap();
    handles[1].debug().await.unwrap();
    handles[2].debug().await.unwrap();

    let pred_0 = handles[0].predecessor().await.expect("node should be running");
    let pred_0 = pred_0.expect("nodes should all be connected");
    let suc_0 = handles[0].successor().await.expect("node should be running");
    let suc_0 = suc_0.expect("nodes should all be connected");
    
    let pred_1 = handles[1].predecessor().await.expect("node should be running");
    let pred_1 = pred_1.expect("nodes should all be connected");
    let suc_1 = handles[1].successor().await.expect("node should be running");
    let suc_1 = suc_1.expect("nodes should all be connected");
    
    let pred_2 = handles[2].predecessor().await.expect("node should be running");
    let pred_2 = pred_2.expect("nodes should all be connected");    
    let suc_2 = handles[2].successor().await.expect("node should be running");
    let suc_2 = suc_2.expect("nodes should all be connected");

    // Verify order
    // Verify predecessors
    assert_eq!(&pred_0, handles[2].get_key(), "node 0's predecessor is not the id of node 2 ");
    println!("pred(0) {:?} == n2 {:?}", pred_0.get_location(), handles[2].get_key().get_location());
    assert_eq!(&pred_1, handles[0].get_key(), "node 1's predecessor is not the id of node 0 ");
    println!("pred(n1) {:?} == n0 {:?}", pred_1.get_location(), handles[0].get_key().get_location());
    assert_eq!(&pred_2, handles[1].get_key(), "node 2's predecessor is not the id of node 1 ");
    println!("pred(n2) {:?} == n1 {:?}", pred_2.get_location(), handles[1].get_key().get_location());
    // Verify successors
    println!("suc(n0) {:?} == n1 {:?}", suc_0.get_location(), handles[1].get_key().get_location());
    assert_eq!(&suc_0, handles[1].get_key(), "node 0's successor is not the id of node 1 ");
    println!("suc(n1) {:?} == n2 {:?}", suc_1.get_location(), handles[2].get_key().get_location());
    assert_eq!(&suc_1, handles[2].get_key(), "node 1's successor is not the id of node 2 ");
    println!("suc(n2) {:?} == n0 {:?}", suc_2.get_location(), handles[0].get_key().get_location());
    assert_eq!(&suc_2, handles[0].get_key(), "node 2's successor is not the id of node 0 ");

    // use 2 to request the predecessor of 1, should return id of 0
    let key_1 = handles[1].get_key().clone();
    let pred_of_1 = handles[2].get_predecessor(&key_1).await.expect("should not time out");
    println!("pred_of_1, {:?}", pred_of_1.sha256());
    assert_eq!(&pred_of_1, handles[1].get_key(), "failed to get correct predecessor key");
}
