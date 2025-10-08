use tokio::sync::mpsc::Sender;

use crate::{
    alias::{AliasOperation, AliasStreamKey},
    error::ChordResult,
    id::{ChordPrivateKey, ChordPublicKey},
};

pub(crate) struct ListenPathEntry {
    key: ChordPrivateKey,
    dest_key: ChordPrivateKey,
    stream_key: AliasStreamKey,
    host: Option<ChordPublicKey>,
    sender: Sender<Vec<u8>>,
}

impl ListenPathEntry {
    pub fn new(
        key: ChordPrivateKey,
        host: Option<ChordPublicKey>,
        sender: Sender<Vec<u8>>,
    ) -> Self {
        let dest_key = ChordPrivateKey::generate();
        Self {
            key,
            dest_key,
            stream_key: AliasStreamKey::generate(),
            host,
            sender,
        }
    }

    pub fn key(&self) -> &ChordPrivateKey {
        &self.key
    }

    pub fn dest_key(&self) -> &ChordPrivateKey {
        &self.dest_key
    }

    pub(crate) fn unwrap(&self, ciphertext: Vec<u8>) -> ChordResult<Vec<u8>> {
        self.stream_key.unwrap(ciphertext)
    }

    pub fn host(&self) -> Option<&ChordPublicKey> {
        self.host.as_ref()
    }

    pub fn set_host(&mut self, pred: Option<ChordPublicKey>) {
        self.host = pred;
    }

    pub async fn send(&self, msg: Vec<u8>) {
        self.sender.send(msg).await;
    }

    pub fn operation_set(&self) -> AliasOperation {
        AliasOperation::Set {
            inc_key: self.key.get_public_key(),
            dest_key: self.dest_key.get_public_key(),
            stream_key: self.stream_key.clone(),
        }
    }
}
