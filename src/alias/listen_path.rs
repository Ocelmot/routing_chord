use std::time::Instant;

use tokio::sync::mpsc::Sender;
use tracing::trace;

use crate::{
    alias::{AliasOperation, AliasStreamKey},
    connections::Connections,
    error::{ChordResult, ErrorKind},
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
};

pub(crate) struct ListenPath {
    sender: Sender<Vec<u8>>,

    /// Entries is a list of hops along the path.
    /// Note: entries starts from the closest hop to this node, and ends at the hop that is the entrance to the path
    entries: Vec<ListenPathEntry>,
}

impl ListenPath {
    pub fn new(listen_key: ChordPrivateKey, sender: Sender<Vec<u8>>, length: usize) -> Self {
        assert!(length >= 1, "Listen paths must have at least one entry");
        let mut entries = Vec::with_capacity(length);
        for _ in 0..length - 1 {
            let new_entry = ListenPathEntry::new(ChordPrivateKey::generate());
            entries.push(new_entry);
        }
        entries.push(ListenPathEntry::new(listen_key));
        Self { sender, entries }
    }

    /// Gets the first entry of the path. All paths have at least one entry
    pub fn first_entry(&self) -> &ListenPathEntry {
        &self.entries[0]
    }

    /// The listen path is distinguished from others based on the location of its first alias.
    pub fn path_loc(&self) -> ChordLocation {
        self.entries
            .first()
            .expect("all aliases have at least one entry")
            .alias_key
            .get_location()
    }

    pub fn sender(&self) -> &Sender<Vec<u8>> {
        &self.sender
    }

    /// Iterate over entries from closest to furthest
    pub fn entries(&self) -> impl Iterator<Item = &ListenPathEntry> {
        self.entries.iter()
    }

    /// Iterate over entries from closest to furthest
    pub fn entries_mut(&mut self) -> impl Iterator<Item = &mut ListenPathEntry> {
        self.entries.iter_mut()
    }

    pub fn unwrap(&self, ciphertext: Vec<u8>) -> ChordResult<Vec<u8>> {
        let mut text = ciphertext;
        for entry in &self.entries {
            text = entry.unwrap(text)?;
        }
        Ok(text)
    }

    pub fn get_entry<L: Into<ChordLocation>>(&mut self, loc: L) -> Option<&mut ListenPathEntry> {
        let loc = loc.into();
        for entry in self.entries.iter_mut() {
            if entry.alias_key.get_location() == loc {
                return Some(entry);
            }
        }
        None
    }

    /// Segment the path into 3 parts, the target entry, the nodes that precede
    /// it, the nodes that follow it.
    /// 
    /// The path is segmented by the alias's keys, not the host's keys because
    /// the host keys are not unique. (more probably repeated in chords with
    /// very few nodes)
    pub fn get_segments<L: Into<ChordLocation>>(
        &mut self,
        loc: L,
    ) -> Option<(
        Vec<&mut ListenPathEntry>,
        &mut ListenPathEntry,
        Vec<&mut ListenPathEntry>,
    )> {
        let loc = loc.into();
        let mut entry_reached = false;
        let mut head = Vec::new();
        let mut found_entry = None;
        let mut tail = Vec::new();
        for entry in self.entries.iter_mut() {
            if entry_reached {
                tail.push(entry);
            } else {
                if entry.alias_key.get_location() == loc {
                    found_entry = Some(entry);
                    entry_reached = true;
                } else {
                    head.push(entry);
                }
            }
        }
        found_entry.map(|entry| (head, entry, tail))
    }

    /// Wraps and sends a message in the reverse direction along this path
    pub async fn send_to(
        &self,
        connections: &mut Connections,
        to: ChordLocation,
        mut msg: AliasOperation,
    ) -> ChordResult {
        trace!("send_to alias at {:?}", &to);
        let mut entry = None;
        let mut head = Vec::new();
        for node in self.entries.iter() {
            if node.alias_key.get_location() == to {
                entry = Some(node);
                break;
            } else {
                head.push(node);
            }
        }
        let entry = entry.ok_or(ErrorKind::NoSuchAlias)?;
        let mut to = entry.host.as_ref().ok_or(ErrorKind::AliasOwner)?;

        trace!("send_to encrypting with key {:?}", entry.host().ok_or(ErrorKind::AliasOwner)?.get_location());
        let data = msg.serialize();
        let mut data = entry
            .host().ok_or(ErrorKind::AliasOwner)? 
            .encrypt_chunked(&data)
            .expect("encryption should succeed");

        // wrap message in all previous entries
        let mut to_alias = entry.alias_key.get_location();
        for entry in head.iter().rev() {
            let host = entry.host.as_ref().ok_or(ErrorKind::AliasOwner)?;
            trace!("send_to wrapping for alias with id {:?}, encrypting with host: {:?}", entry.alias_key.get_location(), host.get_location());
            msg = AliasOperation::Forward { alias_key: entry.alias_key.get_public_key(), to_host: to.get_location(), to_alias, data };
            data = msg.serialize();
            data = host.encrypt_chunked(&data).unwrap();

            to = host;
            to_alias = entry.alias_key.get_location();
        }

        trace!("send_to routing to {:?}", to.get_location());
        let self_id = connections.self_id().clone();
        connections.route_alias_op(to, &self_id, msg).await?;

        Ok(())
    }
}

pub(crate) struct ListenPathEntry {
    /// The key of this alias. Used to verify control of the remote host.
    alias_key: ChordPrivateKey,

    /// Used to decode incoming data
    stream_key: AliasStreamKey,

    /// the location where the listen path alias is actually hosted
    /// If none, predecessor info has not been received yet
    host: Option<ChordPublicKey>, // The originator does not manage the hosts along the chain.

    /// Last time this entry received a response from the node.
    /// If none, set has not yet returned [Established]
    last_active: Option<Instant>,
}

impl ListenPathEntry {
    pub fn new(alias_key: ChordPrivateKey) -> Self {
        Self {
            alias_key,
            stream_key: AliasStreamKey::generate(),
            host: None,
            last_active: None,
        }
    }

    pub fn key(&self) -> &ChordPrivateKey {
        &self.alias_key
    }

    pub fn location(&self) -> ChordLocation {
        self.alias_key.get_location()
    }

    pub fn stream_key(&self) -> &AliasStreamKey {
        &self.stream_key
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

    pub fn last_active(&self) -> &Option<Instant> {
        &self.last_active
    }
    pub fn active_now(&mut self) {
        self.last_active = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {

    use rand::random;
    use tokio::sync::mpsc::channel;

    use crate::alias::manager::DEFAULT_LISTEN_PATH_LENGTH;

    use super::*;

    #[test]
    #[test_log::test]
    fn alias_entry_wrap_unwrap() {
        // Initialize listen path
        // let self_id = ChordPrivateKey::generate();
        let listen_key = ChordPrivateKey::generate();
        let (sender, _receiver) = channel(10);
        let listen_path = ListenPath::new(listen_key, sender, DEFAULT_LISTEN_PATH_LENGTH);

        // encrypt message
        let msg = String::from("Test Message").into_bytes();
        let mut msg_tmp = msg.clone();
        for key in listen_path
            .entries
            .iter()
            .rev()
            .map(|entry| entry.stream_key)
        {
            msg_tmp = key.wrap(random(), &msg_tmp);
        }

        // Now unwrap the message
        let new_msg = listen_path.unwrap(msg_tmp).expect("Message should unwrap");

        // verify
        assert_eq!(msg, new_msg);
    }
}
