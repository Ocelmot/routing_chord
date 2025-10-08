use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use rand::random;
use tracing::{trace, warn, Span};

use crate::{
    alias::AliasOperation,
    connections::Connections,
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
    message::{MemberMessage, Reply, Request},
};

/// The timeout duration for pending replies.
/// Replies that take more than this time will be considered to have failed.
const TIMEOUT: Duration = Duration::from_secs(180);

/// Expiration time for cache entries
const EXPIRATION_LIMIT: Duration = Duration::from_secs(180);

pub struct Requests {
    self_id: ChordPrivateKey,

    pending_replies: HashMap<u64, (u64, ChordLocation, Instant)>,
    our_requests: HashMap<u64, (Request, Instant)>,
    // predecessor cache
    cache: BTreeMap<ChordLocation, (ChordPublicKey, String, Instant)>,

    // Debug
    span: Span,
}

impl Requests {
    pub(crate) fn new(
        self_id: ChordPrivateKey,
        span: &Span,
    ) -> Self {
        Self {
            self_id,

            pending_replies: HashMap::new(),
            our_requests: HashMap::new(),
            cache: BTreeMap::new(),

            span: span.clone(),
        }
    }

    // Possibly the below need to be redone

    /// Creates and routes an alias operation through the chord network.
    #[deprecated]
    pub(crate) async fn route_alias_op(
        &mut self,
        connections: &mut Connections,
        to: &ChordPublicKey,
        from: &ChordPrivateKey,
        msg: AliasOperation,
    ) {
        let serialized = bincode::serialize(&msg).expect("AliasOperations should serialize");
        let sig = from.sign(&serialized).to_vec();
        let msg = MemberMessage::AliasOperation {
            to: to.clone(),
            from: from.get_public_key(),
            op: serialized,
            sig,
        };
        connections.route_msg(to, &msg).await;
    }

    // Request functions

    pub async fn send_request(&mut self, connections: &mut Connections, req: Request) {
        let new_id: u64 = random();
        self.our_requests
            .insert(new_id, (req.clone(), Instant::now()));
        connections
            .route_msg(req.to(), &MemberMessage::Request(new_id, req))
            .await;
    }

    /// Forwards a request from another node.
    /// Adds the id to a list so that a reply can be sent.
    /// Remaps the id
    pub async fn forward_request(&mut self, connections: &mut Connections, id: u64, req: Request, from: ChordLocation) {
        _forward_request(connections, &mut self.pending_replies, id, req, from, ).await;
    }

    pub async fn send_reply(&mut self, connections: &mut Connections, to: ChordLocation, req_id: u64, reply: Reply) {
        trace!("sending reply to {:#?}", to);
        _send_reply(connections, to, req_id, reply).await;
    }

    /// Returns a reply back to the node that requested it.
    pub async fn process_reply(&mut self, connections: &mut Connections, req_id: u64, reply: Reply) -> Option<Reply> {
        // test if this reply is for this node. If it is, test its validity and return it as some
        if self.our_requests.contains_key(&req_id) {
            if reply.verify() {
                self.our_requests.remove(&req_id);
                Some(reply)
            } else {
                None
            }
        } else {
            // if it is not for this node, forward and return none
            let (old_id, key, _) = self.pending_replies.remove(&req_id)?;
            trace!("forwarding reply to {:#?}", key);
            connections
                .member_send(key, &MemberMessage::Reply(old_id, reply))
                .await;
            None
        }
    }

    /// Cleans out old request entries
    pub fn upkeep(&mut self) {
        // Clean old requests
        let cutoff = Instant::now() - TIMEOUT;
        self.pending_replies
            .retain(|_, (_, _, timestamp)| &*timestamp > &cutoff);
    }

    /// Resends pending messages
    pub async fn resend_pending(&mut self, connections: &mut Connections) -> Vec<Request> {
        let mut expired = Vec::new();
        let now = Instant::now();
        self.our_requests.retain(|_, e| {
            let is_expired = e.1 > now - Duration::from_secs(60);
            if is_expired {
                expired.push(e.0.clone());
            }
            is_expired
        });
        for (req_id, (req, _sent)) in &self.our_requests {
            connections
                .member_send(req.to(), &MemberMessage::Request(*req_id, req.clone()))
                .await;
        }
        expired
    }

    // Predecessor requests and cache

    pub fn predecessor_of<L: Into<ChordLocation>>(
        &mut self,
        location: L,
    ) -> Option<(&ChordPublicKey, &String)> {
        let location = location.into();
        let (_, _, cache_time) = self.cache.get(&location)?;
        let expired = *cache_time + EXPIRATION_LIMIT < Instant::now();
        if expired {
            self.cache.remove(&location);
            return None;
        }

        let (cache_key, cache_addr, _) = self.cache.get(&location)?;
        return Some((cache_key, cache_addr));
    }

    pub async fn fetch_predecessor_of<L: Into<ChordLocation>>(
        &mut self,
        connections: &mut Connections,
        location: L,
    ) -> Option<(&ChordPublicKey, &String)> {
        let location = location.into();
        if let Some((_, _, cache_time)) = self.cache.get(&location) {
            if *cache_time + EXPIRATION_LIMIT < Instant::now() {
                trace!("cache entry expired");
                self.cache.remove(&location);
            }
        }

        if !self.cache.contains_key(&location) {
            self.send_request(connections, Request::GetPredecessor {
                location: location.clone(),
            })
            .await;
        }

        self.cache
            .get(&location)
            .map(|(cache_key, cache_addr, _)| (cache_key, cache_addr))
    }

    // Handlers
    pub(crate) async fn handle_get_predecessor(
        &mut self,
        connections: &mut Connections,
        pub_addr: &mut Option<String>,
        req_id: u64,
        from: ChordLocation,
        location: ChordLocation,
    ) {
        if connections.in_controlled_sector(location.clone()) {
            trace!(parent: &self.span, "Replying");
            // reply
            if let Some(addr) = pub_addr {
                let reply = Reply::predecessor_of(&self.self_id, location.clone(), addr.clone());
                _send_reply(connections, from, req_id, reply).await;
            } else {
                warn!(parent: &self.span, "Failed to get public addr");
            }
        } else {
            // route
            trace!(parent: &self.span, "Routing");
            let req = Request::GetPredecessor { location };
            _forward_request(connections, &mut self.pending_replies, req_id, req, from).await;
        }
    }
}

async fn _send_reply(
    connections: &mut Connections,
    to: ChordLocation,
    req_id: u64,
    reply: Reply,
) {
    connections
        .member_send(to, &MemberMessage::Reply(req_id, reply))
        .await;
}

async fn _forward_request(
    connections: &mut Connections,
    pending_replies: &mut HashMap<u64, (u64, ChordLocation, Instant)>,
    id: u64,
    req: Request,
    from: ChordLocation, 
) {
    let new_id: u64 = random();
    pending_replies
        .insert(new_id, (id, from, Instant::now()));
    connections
        .route_msg(req.to(), &MemberMessage::Request(new_id, req))
        .await;
}
