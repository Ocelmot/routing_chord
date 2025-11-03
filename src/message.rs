use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc::Sender, oneshot};

use crate::{
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
    peer::{MessageType, PeerWriter},
};

pub(crate) enum Message {
    Control(ControlMessage),
    Member(ChordPublicKey, MemberMessage),
    Associate(ChordPublicKey, AssociateMessage),
}

#[derive(Debug)]
pub(crate) enum ControlMessage {
    AddMember(PeerWriter<MemberMessage>),
    AddAssociate(PeerWriter<AssociateMessage>),
    ListenAt(ChordPrivateKey, Sender<Vec<u8>>),
    ConnectTo(ChordLocation, Vec<u8>),
    Debug,
    Predecessor(oneshot::Sender<Option<ChordPublicKey>>),
    Successor(oneshot::Sender<Option<ChordPublicKey>>),
    PredecessorOf(oneshot::Sender<ChordPublicKey>, ChordLocation),
    // Terminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Request {
    GetPredecessor { location: ChordLocation },
    GetSuccessor { location: ChordLocation },
}

impl Request {
    pub fn to(&self) -> ChordLocation {
        match self {
            Request::GetPredecessor { location, .. } => location,
            Request::GetSuccessor { location, .. } => location,
        }
        .clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Reply {
    PredecessorOf {
        of: ChordLocation,
        addr: String,
        key: ChordPublicKey,
        sig: Vec<u8>,
    },
    SuccessorOf {
        of: ChordLocation,
        addr: String,
        key: ChordPublicKey,
        sig: Vec<u8>,
    },
}

impl Reply {
    pub(crate) fn predecessor_of(key: &ChordPrivateKey, of: ChordLocation, addr: String) -> Self {
        let mut data = Vec::new();
        data.push(0);
        data.extend_from_slice(&of.as_bytes());
        data.extend_from_slice(&addr.as_bytes());
        let sig = key.sign(&data).to_vec();

        Self::PredecessorOf {
            of,
            addr,
            key: key.get_public_key(),
            sig,
        }
    }

    pub(crate) fn successor_of(key: &ChordPrivateKey, of: ChordLocation, addr: String) -> Self {
        let mut data = Vec::new();
        data.push(1);
        data.extend_from_slice(&of.as_bytes());
        data.extend_from_slice(&addr.as_bytes());
        let sig = key.sign(&data).to_vec();

        Self::SuccessorOf {
            of,
            addr,
            key: key.get_public_key(),
            sig,
        }
    }

    fn index(&self) -> u8 {
        match self {
            Reply::PredecessorOf { .. } => 0,
            Reply::SuccessorOf { .. } => 1,
        }
    }
    pub(crate) fn verify(&self) -> bool {
        match self {
            Reply::PredecessorOf { of, key, addr, sig } => {
                let mut data = Vec::new();
                data.push(self.index());
                data.extend_from_slice(&of.as_bytes());
                data.extend_from_slice(&addr.as_bytes());
                key.verify(&data, &sig)
            }
            Reply::SuccessorOf { of, key, addr, sig } => {
                let mut data = Vec::new();
                data.push(self.index());
                data.extend_from_slice(&of.as_bytes());
                data.extend_from_slice(&addr.as_bytes());
                key.verify(&data, &sig)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum MemberMessage {
    /// Indicates that the node that sent this believes the recipient is its
    /// successor
    Notify,

    /// Response to the stabilize routine's notify message. contains the address of the successor's predecessor
    PredecessorAddr(String),

    // Detect liveness of connection
    Ping,
    Pong,

    // requests and replies
    Request(u64, Request),
    Reply(u64, Reply),

    /// Alias message instructing host node to do some action (Moves in the reverse direction)
    /// 
    /// [AliasOperation]s are serialized, then encrypted, then signed.
    AliasOperation {
        /// The Alias' host node that will perform the action
        to: ChordLocation,

        /// The node requesting the aliasing (possibly on behalf of another node)
        from: ChordPublicKey,

        /// The details of the operation (to be decrypted by the 'to' private key)
        op: Vec<u8>,

        /// Signature to verify the operation came from the 'from' private key
        sig: Vec<u8>,
    },

    AliasResponse {
        /// The host fo the intermediate alias this is being sent to
        /// 
        /// Used to route the data through the chord.
        to: ChordLocation,

        // Need to have the alias id that the message is being sent to, but aliases currently only hold a single dest (the host).
        // The alias could route to the alias id directly, but then would need to do more trail routing, and could give away the end of the path.
        // The alias could now hold both the host as well as the dest alias, but this would also give away the final step in the path.
        // (if the alias and dest are equal it must be to the final step)
        // Therefore there should be some kind of outgoing table that tracks which next hops have been contacted to use as a nat-like routing table
        // This needs to be used in addition to the to-check to handle both cases where its newly routing or intermediate routing.

        /// The alias this is being routed from
        /// 
        /// Used for the final step to find the listen path
        from: ChordLocation,

        /// The response itself
        data: Vec<u8>,
    },

    /// Route some data through the chord, to some alias.
    Data {
        /// The destination to route the data
        to: ChordLocation,

        /// The location of the alias that last relayed the message
        alias_loc: ChordLocation,

        /// Number of hops backward through the chord, when tail routing.
        hop_count: Option<u8>,

        /// The body of the message
        body: Vec<u8>,
    },
}

impl MessageType for MemberMessage {
    fn is_member() -> bool {
        true
    }

    fn should_encrypt(&self) -> bool {
        match self {
            _ => true,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AssociateMessage {
    Ping,
}

impl MessageType for AssociateMessage {
    fn is_member() -> bool {
        false
    }

    fn should_encrypt(&self) -> bool {
        match self {
            _ => true,
        }
    }
}
