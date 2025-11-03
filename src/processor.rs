use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::{
    net::TcpListener,
    select,
    sync::{
        mpsc::{channel, Receiver, Sender},
        oneshot::Sender as OneShotSender,
    },
    task::JoinHandle,
    time::{interval, MissedTickBehavior},
};
use tracing::{debug, error, info, instrument, span, trace, Level, Span};

use crate::{
    alias::manager::{Aliases, DEFAULT_LISTEN_PATH_LENGTH},
    connections::Connections,
    error::{ChordError, ChordResult, ErrorKind, ProblemWrap},
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
    listener::{listen_handler, process_connection_type},
    message::{AssociateMessage, ControlMessage, MemberMessage, Message, Reply, Request},
    peer::connect,
    requests::Requests,
    state::ChordState,
    ChordHandle,
};

pub struct ChordProcessor {
    state: ChordState,
    self_id: ChordPrivateKey,
    predecessor: Option<(ChordPublicKey, String)>,
    next_finger_index: u32,
    public_addr: Option<String>,

    recv_queue: Sender<Vec<u8>>,

    queue_tx: Sender<Message>,
    queue_rx: Receiver<Message>,

    /// map from requested connection to number of connection attempts
    pending_connections: HashMap<ChordLocation, u8>,

    // add a request manager to manage mapping requests
    connections: Connections,
    requests: Requests,
    predecessor_requests: HashMap<ChordLocation, (OneShotSender<ChordPublicKey>, Instant)>,

    aliases: Aliases,

    // Debug
    span: Span,
}

impl ChordProcessor {
    fn new(state: ChordState) -> ChordResult<(Self, Sender<Message>, Receiver<Vec<u8>>, u16)> {
        let self_id = ChordPrivateKey::generate();
        let span = span!(
            Level::DEBUG,
            "Chord",
            AT = format!("{:#?}", self_id.get_location())
        );
        let (recv_queue, recv_rx) = channel(50);
        let (queue_tx, queue_rx) = channel(25);
        let listen_port = state.listen_addr().parse::<SocketAddr>().wrap()?.port();

        let connections = Connections::new(self_id.clone(), listen_port, queue_tx.clone(), &span);
        let requests = Requests::new(self_id.clone(), &span);
        let aliases = Aliases::new(self_id.clone(), &span);

        let processor = ChordProcessor {
            state,
            self_id: self_id.clone(),
            predecessor: None,
            next_finger_index: 0,
            public_addr: None,

            recv_queue,

            queue_tx: queue_tx.clone(),
            queue_rx,

            pending_connections: HashMap::new(),
            connections,
            requests,
            predecessor_requests: HashMap::new(),
            aliases,
            span,
        };

        Ok((processor, queue_tx, recv_rx, listen_port))
    }

    pub(crate) fn host(state: ChordState) -> ChordResult<ChordHandle> {
        let (processor, queue_tx, recv_rx, _) = Self::new(state)?;
        let pub_key = processor.self_id.get_public_key();
        let join_handle = processor.run();
        Ok(ChordHandle::new(pub_key, queue_tx, recv_rx, join_handle))
    }

    pub(crate) async fn join(
        state: ChordState,
        join_addrs: Vec<String>,
    ) -> ChordResult<ChordHandle> {
        debug!("Chord joining...");

        let (mut processor, _, recv_rx, listen_port) = Self::new(state)?;
        let pub_key = processor.self_id.get_public_key();

        // Create a new channel that will replace the default one.
        let (queue_tx, mut queue_rx) = channel(25);

        // start connections to all candidates.
        for addr in processor.state.chord_addrs().cloned() {
            let task_self_id = processor.self_id.clone();
            let task_queue_tx = queue_tx.clone();
            tokio::spawn(async move {
                if let Ok(connection) =
                    connect::<_, MemberMessage>(&task_self_id, addr, listen_port).await
                {
                    process_connection_type(task_queue_tx, connection);
                }
            });
        }
        for addr in join_addrs {
            let task_self_id = processor.self_id.clone();
            let task_queue_tx = queue_tx.clone();
            tokio::spawn(async move {
                if let Ok(connection) =
                    connect::<_, MemberMessage>(&task_self_id, addr, listen_port).await
                {
                    process_connection_type(task_queue_tx, connection);
                }
            });
        }

        let queue_tx = queue_tx.downgrade();
        // wait until one connection succeeds and add it to the members list.
        let first_member = loop {
            if let Some(msg) = queue_rx.recv().await {
                if let Message::Control(ControlMessage::AddMember(member)) = msg {
                    break member;
                }
                // There should be no other kinds of messages
            } else {
                // the connection has closed
                return Err(ChordError::new(ErrorKind::FailedToConnect));
            }
        };
        let queue_tx = queue_tx.upgrade().ok_or(ErrorKind::ChordStopped)?;

        // replace the default channel with the new one
        processor.queue_rx = queue_rx;
        processor.queue_tx = queue_tx.clone();
        processor.connections.replace_channel(queue_tx.clone());

        // add the first connection
        processor.connections.add_member(first_member);

        let join_handle = processor.run();
        Ok(ChordHandle::new(pub_key, queue_tx, recv_rx, join_handle))
    }

    pub(crate) async fn join_or_host(
        state: ChordState,
        join_addrs: Vec<String>,
    ) -> ChordResult<ChordHandle> {
        let (processor, queue_tx, recv_rx, listen_port) = Self::new(state)?;
        let pub_key = processor.self_id.get_public_key();

        // start connections to all candidates.
        for addr in processor.state.chord_addrs().cloned() {
            let task_self_id = processor.self_id.clone();
            let task_queue_tx = queue_tx.clone();
            tokio::spawn(async move {
                if let Ok(connection) =
                    connect::<_, MemberMessage>(&task_self_id, addr, listen_port).await
                {
                    process_connection_type(task_queue_tx, connection);
                }
            });
        }
        for addr in join_addrs {
            let task_self_id = processor.self_id.clone();
            let task_queue_tx = queue_tx.clone();
            tokio::spawn(async move {
                if let Ok(connection) =
                    connect::<_, MemberMessage>(&task_self_id, addr, listen_port).await
                {
                    process_connection_type(task_queue_tx, connection);
                }
            });
        }

        let join_handle = processor.run();
        Ok(ChordHandle::new(pub_key, queue_tx, recv_rx, join_handle))
    }

    // start the loop and process messages
    fn run(mut self) -> JoinHandle<ChordResult> {
        tokio::spawn(async move {
            let listen_addr: SocketAddr = self.state.listen_addr().parse().wrap()?;
            let listener = TcpListener::bind(&listen_addr).await?;

            // configure intervals
            let mut stabilize_interval = interval(*self.state.stabilize_interval());
            stabilize_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut fix_fingers_interval = interval(*self.state.fix_fingers_interval());
            fix_fingers_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut check_predecessor_interval = interval(*self.state.check_predecessor_interval());
            check_predecessor_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            let mut pending_interval = interval(Duration::from_secs(5));
            pending_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                select! {
                    accept_info = listener.accept() => {
                        let (tcp_stream, sock_addr) = match accept_info {
                            Ok(value) => value,
                            Err(e) => {
                                error!("Chord listen socket encountered error: {:?}", e);
                                return ChordResult::Err(e.into());
                            }
                        };
                        listen_handler(self.self_id.clone(), &self.queue_tx, tcp_stream, sock_addr, listen_addr.port());
                    },
                    msg = self.queue_rx.recv() => {
                        let Some(msg) = msg else {
                            error!(parent: self.span, "chord read queue ended");
                            return ChordResult::Err(ChordError::new(ErrorKind::ChordStopped))
                        };
                        match msg {
                            Message::Control(msg) => {
                                self.process_control_msg(msg).await?;
                            }
                            Message::Member(id, msg) => {
                                self.process_member_msg(id, msg).await?;
                            },
                            Message::Associate(id, msg) => {
                                self.process_associate_msg(id, msg).await?;
                            }
                        }
                    }
                    _ = stabilize_interval.tick() => {
                        self.stabilize().await?;
                    }
                    _ = fix_fingers_interval.tick() => {
                        self.fix_fingers().await;
                    }
                    _ = check_predecessor_interval.tick() => {
                        self.check_predecessor().await?;
                    }
                    _ = pending_interval.tick() => {
                        self.handle_pending().await;
                    }
                }
            }
            #[allow(unreachable_code)]
            ChordResult::Ok(())
        })
    }

    // Tasks
    async fn process_control_msg(&mut self, msg: ControlMessage) -> ChordResult {
        trace!("Received control msg");
        match msg {
            ControlMessage::AddMember(writer) => {
                trace!(parent: &self.span, "AddMember{{member={:?}}}", writer.other_id().get_location());
                self.connections.add_member(writer);
            }
            ControlMessage::AddAssociate(writer) => {
                trace!("AddAssociate");
                self.connections.add_associate(writer);
            }
            ControlMessage::ListenAt(alias_key, sender) => {
                trace!(parent: &self.span, "ListenAt");
                self.aliases
                    .listen_at(
                        &mut self.connections,
                        &mut self.requests,
                        alias_key,
                        sender,
                        DEFAULT_LISTEN_PATH_LENGTH,
                    )
                    .await;
            }
            ControlMessage::ConnectTo(conn_loc, msg) => {
                trace!("ConnectTo");

                self.aliases
                    .process_data(
                        &mut self.connections,
                        conn_loc,
                        self.self_id.get_location(),
                        Some(4),
                        msg,
                    )
                    .await;
            }
            ControlMessage::Predecessor(sender) => {
                let _ = sender.send(self.connections.predecessor_key());
            }
            ControlMessage::Successor(sender) => {
                let _ = sender.send(self.connections.successor_key());
            }
            ControlMessage::PredecessorOf(sender, location) => {
                self.predecessor_requests
                    .insert(location.clone(), (sender, Instant::now()));
                self.requests
                    .send_request(&mut self.connections, Request::GetPredecessor { location })
                    .await;
            }
            ControlMessage::Debug => {
                trace!("Debugging");
                println!(
                    "===== Debug for {:?} =====",
                    self.self_id.get_public_key().get_location()
                );
                match self.connections.successor_key() {
                    Some(key) => println!("Successor: {:?}", key.get_location()),
                    None => println!("Successor: None"),
                }

                match self.predecessor.as_ref().map(|e| &e.0) {
                    Some(key) => println!("Predecessor: {:?}", key.get_location()),
                    None => println!("Predecessor: None"),
                }
                println!("Members:");
                for member_key in self.connections.members() {
                    println!("\t-> {:?}", member_key.get_location());
                }
            }
        }
        Ok(())
    }

    async fn process_member_msg(&mut self, id: ChordPublicKey, msg: MemberMessage) -> ChordResult {
        match msg {
            // Step 3 of the stabilize procedure. This node has received a message
            // indicating that some other node thinks it is this node's predecessor.
            // This claim will be verified.
            MemberMessage::Notify => {
                self.process_notify(id).await;
            }

            MemberMessage::Request(req_id, req) => match req {
                Request::GetPredecessor { location } => {
                    trace!(parent: &self.span, "Processing get_pred");
                    self.process_get_predecessor(req_id, id.get_location(), location)
                        .await;
                }
                Request::GetSuccessor { location } => {
                    trace!(parent: &self.span, "Processing get_successor");
                    self.process_get_successor(req_id, id.get_location(), location)
                        .await;
                }
            },
            MemberMessage::Reply(req_id, reply) => {
                if let Some(reply) = self
                    .requests
                    .process_reply(&mut self.connections, req_id, reply)
                    .await
                {
                    match reply {
                        Reply::PredecessorOf { of, key, addr, .. } => {
                            self.process_predecessor_of(of, key, addr).await
                        }
                        Reply::SuccessorOf { of, key, addr, .. } => {
                            self.process_successor_of(of, key, addr).await
                        }
                    }
                }
            }

            MemberMessage::PredecessorAddr(addr) => {
                let span = span!(parent: &self.span, Level::DEBUG, "PredecessorAddr");
                let guard = span.enter();
                debug!(parent: &span, "Got addr: {}", addr);
                if let Some(s_loc) = self.connections.successor_key() {
                    // only respond to these messages from our successor
                    if id.get_location() == s_loc.get_location() {
                        debug!(parent: &span, "Connecting to {}", addr);
                        self.connections.connect_to(addr);
                    } else {
                        debug!(parent: &span, "Addr did not come from successor");
                    }
                } else {
                    debug!(parent: &span, "have no successor (message came from nowhere?)");
                }
                drop(guard);
            }
            MemberMessage::Ping => {
                self.connections
                    .member_send(&id, &MemberMessage::Pong)
                    .await;
            }
            MemberMessage::Pong => {} // the ping-pong is complete
            MemberMessage::AliasOperation { to, from, op, sig } => {
                self.aliases
                    .handle_operation(&mut self.connections, &mut self.requests, to, from, op, sig)
                    .await;
            }
            MemberMessage::AliasResponse {
                to,
                from,
                data,
            } => {
                if to == self.self_id.get_location() {
                    trace!(parent: &self.span, "processor got AliasResponse");
                    let result = self.aliases
                        .handle_response(&mut self.connections, to, from, data)
                        .await;
                    trace!("result of alias response = {:?}", result);
                } else {
                    self.connections
                        .route_msg(
                            to.clone(),
                            &MemberMessage::AliasResponse {
                                to,
                                from,
                                // sig,
                                data,
                            },
                        )
                        .await;
                }
            }
            MemberMessage::Data {
                to,
                alias_loc,
                hop_count,
                body: data,
            } => {
                trace!(parent: &self.span, "processor routing data");
                self.aliases
                    .process_data(&mut self.connections, to, alias_loc, hop_count, data)
                    .await;
            }
        }
        Ok(())
    }

    #[instrument(parent = &self.span, level="debug", name="Notify", skip(self, id))]
    async fn process_notify(&mut self, id: ChordPublicKey) {
        // debug!("Notified from {:#?}", id.get_location());
        let Some(peer_listen_addr) = self.connections.member_listen_addr(&id) else {
            // debug!("failed to get member for {:#?}", id.get_location());
            return;
        };

        if let Some((pred_key, pred_addr)) = &self.predecessor {
            // let location = id.get_location();
            if id.get_location().is_in_open_sector(pred_key, &self.self_id) {
                // notify came from a node between our predecessor and us, we should update
                // debug!("notify came from closer than actual predecessor, updating this nodes pred");
                self.predecessor = Some((id, peer_listen_addr.to_string()));
            } else if id == *pred_key {
                // debug!("notify came from actual predecessor, no need to update");
                // notify came from our predecessor, all is well
            } else {
                // notify came from a node behind our predecessor, inform them of our predecessor
                // let msg = MemberMessage::PredecessorOf { to: (), of: (), key: (), addr: (), sig: () };
                // debug!(
                //     "sending predecessor_addr {} to {:#?}",
                //     pred_addr,
                //     id.get_location()
                // );

                self.connections
                    .member_send(&id, &MemberMessage::PredecessorAddr(pred_addr.clone()))
                    .await;
            }
        } else {
            // We currently have no predecessor, we will use the incoming one
            // debug!(
            //     "this node has no predecessor, assigning from notify. addr={}",
            //     peer_listen_addr.to_string()
            // );
            self.predecessor = Some((id, peer_listen_addr.to_string()));
        }
    }

    async fn process_get_predecessor(
        &mut self,
        req_id: u64,
        from: ChordLocation,
        location: ChordLocation,
    ) {
        self.requests
            .handle_get_predecessor(
                &mut self.connections,
                &mut self.public_addr,
                req_id,
                from,
                location,
            )
            .await;
    }

    async fn process_predecessor_of(
        &mut self,
        of: ChordLocation,
        key: ChordPublicKey,
        addr: String,
    ) {
        trace!(parent: &self.span, "Got PredecessorOf");

        // if this is a response to a pending connection
        if self.pending_connections.remove(&of).is_some() {
            if self.connections.contains_member(&key.get_location()) {
                self.connections
                    .member_send(&key, &MemberMessage::Ping)
                    .await;
            } else {
                self.connections.connect_to(addr);
            }
        }

        // if this response could satisfy a listen path
        let _ = self.aliases
            .handle_predecessor_of(&mut self.connections, &of, &key)
            .await;

        // If this response could satisfy a request
        if let Some((sender, _)) = self.predecessor_requests.remove(&of) {
            let _ = sender.send(key);
        }
    }

    async fn process_get_successor(
        &mut self,
        req_id: u64,
        from: ChordLocation,
        location: ChordLocation,
    ) {
        if self.connections.in_controlled_sector(location.clone()) {
            // reply
            let successor_addr =
                self.connections
                    .successor_key()
                    .map_or(self.public_addr.clone(), |e| {
                        self.connections
                            .member_listen_addr(&e)
                            .as_ref()
                            .map(SocketAddr::to_string)
                    });
            if let Some(addr) = successor_addr {
                let reply = Reply::successor_of(&self.self_id, location, addr);
                self.requests
                    .process_reply(&mut self.connections, req_id, reply)
                    .await;
            }
        } else {
            // route
            let req = Request::GetPredecessor { location };
            self.requests
                .forward_request(&mut self.connections, req_id, req, from)
                .await;
        }
    }

    async fn process_successor_of(&mut self, of: ChordLocation, key: ChordPublicKey, addr: String) {
        trace!("Got SuccessorOf");
        todo!("Why do we want to know the successor?");
    }

    async fn process_associate_msg(
        &mut self,
        id: ChordPublicKey,
        msg: AssociateMessage,
    ) -> ChordResult {
        todo!()
    }

    /// Starts the stabilize procedure.
    /// Sequence: stabilize -> get_predecessor -> predecessor -> notify
    #[instrument(parent = &self.span, level="debug", name="Stabilize", skip(self))]
    async fn stabilize(&mut self) -> ChordResult {
        // debug!("Stabilizing");
        // notify our successor. If we are not the successor's predecessor it
        // will reply with its predecessor so we could establish the connection
        if let Some(successor) = self.connections.successor_key() {
            self.connections
                .member_send(&successor, &MemberMessage::Notify)
                .await;
        }

        Ok(())
    }
    async fn fix_fingers(&mut self) {
        let self_location = self.self_id.get_location();
        let finger = self_location.calculate_finger(self.next_finger_index);
        self.next_finger_index = ChordLocation::next_index(self.next_finger_index);

        // calculate public address
        self.public_addr = self.connections.determine_pub_addr();

        if let Some(addr) = self
            .requests
            .predecessor_of(finger.clone())
            .map(|(_, addr)| addr.to_owned())
        {
            self.connections.connect_to(addr);
        } else {
            self.pending_connections.insert(finger, 0);
        }
    }

    async fn check_predecessor(&mut self) -> ChordResult {
        let Some((pred_key, _)) = &self.predecessor else {
            return Ok(());
        };
        let pred_loc = pred_key.get_location();

        self.connections
            .member_send(pred_loc.clone(), &MemberMessage::Ping)
            .await;

        if !self.connections.contains_member(&pred_loc) {
            self.predecessor = None;
        }

        Ok(())
    }

    async fn handle_pending(&mut self) {
        // process pending connection requests
        info!(parent: &self.span, "Node handling pending operations");
        info!(parent: &self.span, "queue len {}", self.queue_rx.len());
        let expired = self.requests.resend_pending(&mut self.connections).await;
        for request in expired {
            match request {
                Request::GetPredecessor { location } => {
                    self.pending_connections.remove(&location);
                }
                _ => {}
            }
        }

        // Use this to make sure that paths are built or can be rebuilt
        // let _ = self.aliases
        //     .handle_pending(&mut self.connections, &mut self.requests)
        //     .await;
    }
}
