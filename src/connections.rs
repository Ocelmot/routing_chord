use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    ops::Bound::{Excluded, Included, Unbounded},
};

use tokio::sync::mpsc::{Sender, error::TrySendError};
use tracing::{error, trace, warn, Span};

use crate::{
    alias::{AliasId, AliasOperation}, error::ChordResult, id::{ChordLocation, ChordPrivateKey, ChordPublicKey}, listener::process_connection_type, message::{AssociateMessage, MemberMessage, Message}, peer::{connect, PeerWriter}
};

const MAX_TRAIL_LENGTH: u8 = 5;

pub(crate) struct Connections {
    self_id: ChordPrivateKey,
    self_location: ChordLocation,
    listen_port: u16,
    queue_tx: Sender<Message>,

    members: BTreeMap<ChordLocation, PeerWriter<MemberMessage>>,
    associates: HashMap<ChordPublicKey, PeerWriter<AssociateMessage>>,

    span: Span,
}

impl Connections {
    pub fn new(
        self_id: ChordPrivateKey,
        listen_port: u16,
        queue_tx: Sender<Message>,
        span: &Span,
    ) -> Self {
        let self_location = self_id.get_location();
        Self {
            self_id,
            self_location,
            listen_port,
            queue_tx,

            members: BTreeMap::new(),
            associates: HashMap::new(),

            span: span.clone(),
        }
    }

    pub(crate) fn self_id(&self) -> &ChordPrivateKey {
        &self.self_id
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub(crate) fn channel_ref(&self) -> &Sender<Message> {
        &self.queue_tx
    }

    pub(crate) fn replace_channel(&mut self, channel: Sender<Message>) {
        self.queue_tx = channel;
    }

    pub(crate) fn connect_to(&self, addr: String) {
        trace!(parent: &self.span, "connect to channel closed: {}", self.queue_tx.is_closed());
        let Ok(addr) = addr.parse::<SocketAddr>() else {
            warn!(parent: &self.span, "Failed to parse addr {}", addr);
            return;
        };
        if self.is_connected_to(addr) {
            trace!(parent: &self.span, "Already connected to {}", addr);
            return;
        }
        let span = self.span.clone();
        let self_id = self.self_id.clone();
        let queue_tx = self.queue_tx.clone();
        let listen_port = self.listen_port;
        tokio::spawn(async move {
            if let Ok(connection) = connect::<_, MemberMessage>(&self_id, addr, listen_port).await {
                trace!(parent: &span, "Connected to {}, processing", addr);
                trace!(parent: &span, "spawn inner channel closed: {}", queue_tx.is_closed());
                process_connection_type(queue_tx, connection);
            } else {
                error!(parent: span, "Failed to connect to {}", addr);
            }
        });
    }

    // Member management functions

    pub fn add_member(&mut self, member: PeerWriter<MemberMessage>) {
        self.members
            .insert(member.other_id().get_location(), member);
    }

    pub fn contains_member(&self, id: &ChordLocation) -> bool {
        self.members.contains_key(id)
    }

    pub fn members(&self) -> impl Iterator<Item = &ChordPublicKey> {
        self.members.iter().map(|(_, x)| x.other_id())
    }

    pub fn member_addr<L: Into<ChordLocation>>(&self, location: L) -> Option<String> {
        self.members
            .get(&location.into())
            .map(|member| member.other_addr())
    }

    pub fn member_listen_addr<L: Into<ChordLocation>>(&self, location: L) -> Option<SocketAddr> {
        self.members
            .get(&location.into())
            .map(|member| member.listen_addr())
    }

    pub fn is_connected_to(&self, addr: SocketAddr) -> bool {
        for (_, writer) in &self.members {
            if writer.listen_addr() == addr {
                return true;
            }
        }
        return false;
    }

    pub(crate) fn determine_pub_addr(&self) -> Option<String> {
        trace!(parent: &self.span, "Determining public address");
        let mut addrs = HashMap::<&IpAddr, usize>::new();
        for (_, member) in &self.members {
            let count = addrs.entry(member.pub_addr()).or_default();
            *count += 1;
        }
        let addr = addrs
            .iter()
            .max_by(|(_, a), (_, b)| a.cmp(b))
            .map(|(addr, _)| (*addr).to_string());

        trace!(parent: &self.span, "Determined public address to be {:?}", addr);
        addr
    }

    pub(crate) fn predecessor_key(&self) -> Option<ChordPublicKey> {
        // if the lower section has an element
        if self
            .members
            .range((Unbounded, Excluded(&self.self_location)))
            .last()
            .is_some()
        {
            // get and return the element
            self.members
                .range((Unbounded, Excluded(&self.self_location)))
                .last()
                .map(|(_, peer)| peer.other_id().clone())
        } else {
            // get and return the last element in the upper section
            self.members
                .range((Excluded(&self.self_location), Unbounded))
                .last()
                .map(|(_, peer)| peer.other_id().clone())
        }
    }

    pub(crate) fn successor_key(&self) -> Option<ChordPublicKey> {
        // if the upper section has an element
        if self
            .members
            .range((Excluded(&self.self_location), Unbounded))
            .next()
            .is_some()
        {
            // get and return the element
            self.members
                .range((Excluded(&self.self_location), Unbounded))
                .next()
                .map(|(_, peer)| peer.other_id().clone())
        } else {
            // get and return the next element in the lower section
            self.members
                .range((Unbounded, Excluded(&self.self_location)))
                .next()
                .map(|(_, peer)| peer.other_id().clone())
        }
    }

    // Associate management functions
    pub fn add_associate(&mut self, member: PeerWriter<AssociateMessage>) {
        self.associates.insert(member.other_id().clone(), member);
    }

    /// The controlled sector for this node is the interval (<This node's location>, <Successor's location>].
    pub(crate) fn in_controlled_sector<L: Into<ChordLocation>>(&self, location: L) -> bool {
        let location = location.into();
        let self_location = self.self_location.clone();
        if let Some(successor_key) = self.successor_key() {
            location.is_in_half_open_sector(self_location, &successor_key)
        } else {
            // if there is no successor, this is the only node, which means it
            // owns the whole chord
            true
        }
    }

    /// sends a message back to the main queue as if this node had sent the
    /// message over the network.
    pub(crate) fn send_self(&self, msg: MemberMessage){
        match self.queue_tx.try_send(Message::Member(self.self_id.get_public_key(), msg)) {
            Ok(_) => {},
            Err(TrySendError::Full(msg)) => {
                // stupid
                let sender = self.queue_tx.clone();
                tokio::spawn(async move{
                    sender.send(msg).await;
                });
            },
            Err(TrySendError::Closed(_)) => {}
        }
    }

    /// Send a message directly to a connected member. This does no routing by
    /// itself.
    pub(crate) async fn member_send<L: Into<ChordLocation>>(
        &mut self,
        to: L,
        msg: &MemberMessage,
    ) -> bool {
        let loc = to.into();
        if let Some(member) = self.members.get_mut(&loc) {
            match member.write(msg).await {
                Ok(_) => true,
                Err(_) => {
                    // if the connection errored, remove it
                    self.members.remove(&loc);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Sends a message to this node's direct predecessor
    pub(crate) async fn predecessor_send(&mut self, msg: &MemberMessage) -> bool {
        if let Some((_, pred)) = self
            .members
            .range_mut((Unbounded, Excluded(&self.self_location)))
            .last()
        {
            return pred.write(msg).await.is_ok();
        }
        if let Some((_, pred)) = self
            .members
            .range_mut((Excluded(&self.self_location), Unbounded))
            .last()
        {
            return pred.write(msg).await.is_ok();
        }
        false
    }

    /// Send a message to an associate.
    pub(crate) async fn associate_send(
        &mut self,
        to: &ChordPublicKey,
        msg: &AssociateMessage,
    ) -> bool {
        if let Some(associate) = self.associates.get_mut(to) {
            match associate.write(msg).await {
                Ok(_) => true,
                Err(_) => {
                    // if the connection errored, remove it
                    self.associates.remove(to);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Route a message to a location. This will route the message to the
    /// closest member before the target location.
    pub(crate) async fn route_msg<L: Into<ChordLocation>>(
        &mut self,
        to: L,
        msg: &MemberMessage,
    ) -> bool {
        let target = to.into();
        let span = self.span.clone();
        trace!(parent: &span,
            "routing message from {:?} to {:?}, member count: {}",
            self.self_location,
            target,
            self.members.len()
        );

        // Does the section to be searched cross the wrap point?
        loop {
            if self.self_location > target {
                // crosses the wrap point.

                // since we want the first connection before the target, start by
                // searching the lower portion first
                if let Some((member_location, member)) = self
                    .members
                    .range_mut((Unbounded, Included(&target)))
                    .last()
                {
                    match member.write(msg).await {
                        Ok(_) => return true,
                        Err(_) => {
                            trace!(parent: &span, "connection errored, trying next");
                            let loc = member_location.clone();
                            // remove member and try again
                            self.members.remove(&loc);
                            continue;
                        }
                    }
                }
                // since the portion between the wrap point and the target is empty,
                // check between ourselves and the wrap point
                if let Some((member_location, member)) = self
                    .members
                    .range_mut((Excluded(&self.self_location), Unbounded))
                    .last()
                {
                    match member.write(msg).await {
                        Ok(_) => return true,
                        Err(_) => {
                            trace!(parent: &span, "connection errored, trying next");
                            let loc = member_location.clone();
                            // remove member and try again
                            self.members.remove(&loc);
                            continue;
                        }
                    }
                }
            } else {
                // does not cross the wrap point
                if let Some((member_location, member)) = self
                    .members
                    .range_mut((Excluded(&self.self_location), Included(&target)))
                    .last()
                {
                    match member.write(msg).await {
                        Ok(_) => return true,
                        Err(_) => {
                            trace!(parent: &span, "connection errored, trying next");
                            let loc = member_location.clone();
                            // remove member and try again
                            self.members.remove(&loc);
                            continue;
                        }
                    }
                }
            }
            trace!(parent: &span, "Did not send, no connections between self and target, remaining members: {}", self.members.len());
            return false;
        }
    }

    /// Creates and routes an alias operation through the chord network.
    pub(crate) async fn route_alias_op(
        &mut self,
        to: &ChordPublicKey,
        from: &ChordPrivateKey,
        op: AliasOperation,
    ) -> ChordResult {
        let serialized = op.serialize();
        let encrypted = to.encrypt_chunked(&serialized)?;
        let sig = from.sign(&encrypted).to_vec();

        let msg = MemberMessage::AliasOperation {
            to: to.get_location(),
            from: from.get_public_key(),
            op: encrypted,
            sig,
        };
        if to == &self.self_id.get_public_key() {
            self.send_self(msg);
        }else{
            self.route_msg(to, &msg).await;
        }
        Ok(())
    }

    /// Route a message to a location. This will route the message to the
    /// closest member before the target location. If the target is in the
    /// owned section of this node, it instead routes the message to the
    /// predecessor and sets the hop count to 0. If the hop count is zero,
    /// the message is routed to the predecessor.
    pub(crate) async fn route_data(
        &mut self,
        to: ChordLocation,
        alias_loc: ChordLocation,
        hop_count: Option<u8>,
        data: Vec<u8>,
    ) {
        trace!(parent: &self.span, "connection routing data");
        // is the data routing normally, or in the trail?
        if let Some(hop_count) = hop_count {
            // routing in the trail
            if hop_count > MAX_TRAIL_LENGTH {
                return;
            }
            let msg = MemberMessage::Data {
                to,
                // alias_id,
                alias_loc,
                hop_count: Some(hop_count + 1),
                body: data,
            };
            self.predecessor_send(&msg).await;
        } else {
            // routing normally
            // if the data would be routed to our sector, switch to routing along the trail.
            if self.in_controlled_sector(to.clone()) {
                let msg = MemberMessage::Data {
                    to,
                    // alias_id,
                    alias_loc,
                    hop_count: Some(0),
                    body: data,
                };
                self.predecessor_send(&msg).await;
            } else {
                let msg = MemberMessage::Data {
                    to: to.clone(),
                    // alias_id,
                    alias_loc,
                    hop_count,
                    body: data,
                };
                self.route_msg(to, &msg).await;
            }
        }
    }
}
