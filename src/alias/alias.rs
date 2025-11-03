use std::{
    collections::VecDeque,
    fmt::{Debug, Display},
    io::Read,
    time::{Duration, Instant},
};

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::{span, trace, Level, Span};

use crate::{
    error::{ChordError, ChordResult, ErrorKind, ProblemWrap},
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
};

const ALIAS_EXPIRY: Duration = Duration::from_secs(15 * 60); // 15 mins

#[derive(Serialize, Deserialize)]
pub(crate) enum AliasOperation {
    /// The parameters required to create the alias entry on the destination system
    Set {
        /// The key of the hosted alias. Used to verify operations on the alias
        alias_key: ChordPublicKey,

        /// Key to wrap incoming traffic
        stream_key: AliasStreamKey,
    },

    /// The hosting node will get the alias and return it down the link
    GetPred(ChordPublicKey, ChordLocation),

    /// Request that the alias host will return a ping
    Ping(ChordPublicKey),

    /// Causes the recipient to forward the message to another node as itself.
    /// the message is encrypted with the dest key, it should also be unwrapped.
    Forward {
        alias_key: ChordPublicKey,
        to_host: ChordLocation,
        to_alias: ChordLocation,
        data: Vec<u8>,
    },
}

impl AliasOperation {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("AliasOperations should serialize in all cases")
    }
    pub(crate) fn deserialize(bytes: &[u8]) -> ChordResult<Self> {
        bincode::deserialize(bytes).wrap()
    }
}

impl std::fmt::Debug for AliasOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set {
                alias_key,
                stream_key: _,
            } => f
                .debug_struct("Set")
                .field("alias_key", &alias_key.get_location())
                .field("stream_key", &"--")
                .finish(),
            Self::GetPred(arg0, arg1) => f
                .debug_tuple("GetPred")
                .field(&arg0.get_location())
                .field(arg1)
                .finish(),
            Self::Ping(arg0) => f.debug_tuple("Ping").field(&arg0.get_location()).finish(),
            Self::Forward {
                alias_key,
                to_host,
                to_alias,
                data: _,
            } => f
                .debug_struct("Forward")
                .field("alias_key", &alias_key.get_location())
                .field("to_host", to_host)
                .field("to_alias", to_alias)
                .field("data", &"--")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum AliasResponse {
    Established,
    Alive,
    Pred {
        pred: ChordPublicKey,
        of: ChordLocation,
    },
    Stopped,
    Wrapped(Vec<u8>),
}

impl AliasResponse {
    pub fn serialize_encrypt(&self, to: &ChordPublicKey) -> ChordResult<Vec<u8>> {
        trace!("encrypting with: {:?}", to.get_location());
        let bytes = serde_cbor::to_vec(self).problem_wrap(ErrorKind::Serialize)?;
        let encrypted = to
            .encrypt_chunked(&bytes)
            .problem_wrap(ErrorKind::Encrypt)?;
        Ok(encrypted)
    }

    pub fn decrypt_deserialize(self_id: &ChordPrivateKey, bytes: &[u8]) -> ChordResult<Self> {
        trace!("decrypting with: {:?}", self_id.get_location());
        let decrypted = self_id
            .decrypt_chunked(bytes)
            .problem_wrap(ErrorKind::Decrypt)?;
        serde_cbor::de::from_slice(&decrypted).problem_wrap(ErrorKind::Deserialize)
    }
}

impl Display for AliasResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AliasResponse::")?;
        match self {
            AliasResponse::Established => write!(f, "Established"),
            AliasResponse::Alive => write!(f, "Alive"),
            AliasResponse::Pred { pred, of } => {
                write!(f, "Pred(pred:{:?}, of:{:?})", pred.get_location(), of)
            }
            AliasResponse::Stopped => write!(f, "Stopped"),
            AliasResponse::Wrapped(_items) => write!(f, "Wrapped(..)"),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub(crate) struct AliasStreamKey {
    key: [u8; 32],
}

impl AliasStreamKey {
    pub fn generate() -> Self {
        let key: [u8; 32] = ChaCha20Poly1305::generate_key(&mut OsRng).into();
        Self { key }
    }
    pub fn get_key(&self) -> Key {
        Key::from(self.key)
    }

    pub(crate) fn encrypt(&self, nonce: AliasNonce, plaintext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from(nonce);

        let cipher = ChaCha20Poly1305::new(&self.get_key());

        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();

        ciphertext
    }

    pub(crate) fn wrap(&self, nonce: AliasNonce, plaintext: &[u8]) -> Vec<u8> {
        trace!("Wrapping with {:?}", self);
        let data = self.encrypt(nonce, plaintext);
        let mut x = Vec::from(nonce);
        x.extend_from_slice(&data);
        x
    }

    pub(crate) fn decrypt(&self, nonce: AliasNonce, ciphertext: &[u8]) -> ChordResult<Vec<u8>> {
        let nonce = Nonce::from(nonce);
        let cipher = ChaCha20Poly1305::new(&self.get_key());

        match cipher.decrypt(&nonce, ciphertext) {
            Ok(data) => Ok(data),
            Err(_) => Err(ChordError::new(ErrorKind::Deserialize)),
        }
    }

    pub(crate) fn unwrap(&self, ciphertext: Vec<u8>) -> ChordResult<Vec<u8>> {
        trace!("Unwrapping with {:?}", self);
        let mut nonce_bytes = [0u8; 12];
        let mut dec = VecDeque::from(ciphertext);
        dec.read_exact(&mut nonce_bytes).wrap()?;
        // since the vec dec is just made now, it will be continuous, so we can take the first slice easily
        let ciphertext = dec.as_slices().0;
        self.decrypt(nonce_bytes, ciphertext)
    }
}

impl Debug for AliasStreamKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ASK:")?;
        for byte in &self.key[0..3] {
            write!(f, "{:02X?}", byte)?;
        }
        Ok(())
    }
}

type AliasNonce = [u8; 12];

pub(crate) struct HostedAliasEntry {
    /// Used to verify operations on this alias entry, determines its 'position' in the chord
    alias_key: ChordPublicKey,

    /// The key that the alias forwards data to.
    /// The destination key is determined by the operation's from entry
    dest_key: ChordPublicKey,

    /// Used by the ultimate receiver to disambiguate its streams
    /// But, is maintained throughout the path to maintain appearances
    // dest_alias_id: AliasId,

    /// Used to wrap incoming communication, before it is forwarded
    stream_key: AliasStreamKey,
    /// Nonce used with stream key
    nonce: BigUint,

    /// Last time this alias saw any data, used to purge old aliases
    last_active: Instant,
}

impl HostedAliasEntry {
    pub(crate) fn new(
        alias_key: ChordPublicKey,
        dest_key: ChordPublicKey,
        stream_key: AliasStreamKey,
    ) -> Self {
        Self {
            alias_key,
            dest_key,
            stream_key,
            nonce: BigUint::ZERO,
            last_active: Instant::now(),
        }
    }

    /// The location where this alias entry lives on the chord
    pub(crate) fn alias_key(&self) -> &ChordPublicKey {
        &self.alias_key
    }

    /// The key of the node that is the target of the alias
    pub(crate) fn dest_key(&self) -> &ChordPublicKey {
        &self.dest_key
    }

    /// The key the alias uses to do the encryption
    pub(crate) fn get_stream_key(&self) -> AliasStreamKey {
        self.stream_key
    }

    pub(crate) fn wrap(&mut self, plaintext: &Vec<u8>) -> Vec<u8> {
        let mut nonce_vec = self.nonce.to_bytes_le();
        nonce_vec.resize(12, 0);
        let nonce_bytes = TryInto::<AliasNonce>::try_into(nonce_vec).unwrap();
        let ciphertext = self.stream_key.wrap(nonce_bytes, plaintext);

        self.last_active = Instant::now();
        self.nonce += 1u32;
        ciphertext
    }

    pub(crate) fn unwrap(&mut self, ciphertext: Vec<u8>) -> ChordResult<Vec<u8>> {
        self.stream_key.unwrap(ciphertext)
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.last_active + ALIAS_EXPIRY < Instant::now()
    }

    pub(crate) fn span(&self, parent: Option<&Span>) -> Span {
        match parent {
            Some(parent) => {
                span!(parent: parent, Level::DEBUG, "Alias", AT = format!("{:#?}=>{:#?}", self.alias_key.get_location(), self.dest_key().get_location()))
            }
            None => span!(
                Level::DEBUG,
                "Alias",
                AT = format!(
                    "{:#?}=>{:#?}",
                    self.alias_key.get_location(),
                    self.dest_key().get_location()
                )
            ),
        }
    }
}

#[cfg(test)]
mod tests {

    use rand::random;

    use super::*;

    #[test]
    #[test_log::test]
    fn alias_stream_key_wrap_round_trip() {
        let data: [u8; 10] = random();
        let nonce: AliasNonce = random();
        let stream_key = AliasStreamKey::generate();

        // wrap
        let transmitted_msg = stream_key.wrap(nonce, &data);

        // unwrap
        let recvd_data = stream_key
            .unwrap(transmitted_msg)
            .expect("message should unwrap");

        // verify
        assert_eq!(
            data, *recvd_data,
            "message received is not equal to that sent"
        );
    }

    #[test]
    #[test_log::test]
    fn alias_stream_key_wrap_round_trip_failure() {
        let data: [u8; 10] = random();
        let nonce: AliasNonce = random();
        let stream_key = AliasStreamKey::generate();

        // wrap
        let mut transmitted_msg = stream_key.wrap(nonce, &data);

        // add corruption to message
        transmitted_msg[15] = transmitted_msg[15].wrapping_add(56);

        // unwrap
        let recvd_data = stream_key.unwrap(transmitted_msg);
        assert!(
            recvd_data.is_err(),
            "corruption should cause the unwrap to fail"
        );
    }

    #[test]
    #[test_log::test]
    fn alias_stream_key_wrap_round_trip_nonce_failure() {
        let data: [u8; 10] = random();
        let nonce: AliasNonce = random();
        let stream_key = AliasStreamKey::generate();

        // wrap
        let mut transmitted_msg = stream_key.wrap(nonce, &data);

        // add corruption to message
        transmitted_msg[5] = transmitted_msg[5].wrapping_add(56);

        // unwrap
        let recvd_data = stream_key.unwrap(transmitted_msg);
        assert!(
            recvd_data.is_err(),
            "corruption should cause the unwrap to fail"
        );
    }
}
