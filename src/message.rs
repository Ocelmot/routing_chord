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
    ConnectTo(ChordPublicKey, Vec<u8>),
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

    // create alias
    AliasOperation {
        to: ChordPublicKey,
        from: ChordPublicKey,
        op: Vec<u8>,
        sig: Vec<u8>,
    },
    /// The location of the alias, the number of hops backwards through the chord, the data itself
    Data {
        to: ChordLocation,
        alias_id: ChordLocation,
        hop_count: Option<u8>,
        data: Vec<u8>,
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
