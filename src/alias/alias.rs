use std::{collections::VecDeque, io::Read, time::{Duration, Instant}};

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use num_bigint::BigUint;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    error::{ChordError, ChordResult, ErrorKind, ProblemWrap},
    id::{ChordLocation, ChordPublicKey},
};


const ALIAS_EXPIRY: Duration = Duration::from_secs(15 * 60); // 15 mins

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum AliasOperation {
    /// The parameters required to create the alias entry on the destination system
    Set { inc_key: ChordPublicKey, dest_key: ChordPublicKey, stream_key: AliasStreamKey },
    /// Send the message from the alias node. Used to extend the path
    Forward(Vec<u8>),
}



#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

    pub(crate) fn encrypt(&mut self, nonce: AliasNonce, plaintext: &[u8]) -> Vec<u8> {
        
        let nonce = Nonce::from(nonce);

        let cipher = ChaCha20Poly1305::new(&self.get_key());

        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();

        ciphertext
    }

    pub(crate) fn wrap(&mut self, nonce: AliasNonce, plaintext: &[u8]) -> Vec<u8> {
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
        let mut nonce_bytes = [0u8; 12];
        let mut dec = VecDeque::from(ciphertext);
        dec.read_exact(&mut nonce_bytes).wrap()?;
        // since the vec dec is just made now, it will be continuous, so we can take the first slice easily
        let ciphertext = dec.as_slices().0;
        self.decrypt(nonce_bytes, ciphertext)
    }

}

type AliasNonce = [u8; 12];

pub(crate) struct AliasEntry {
    key: ChordPublicKey,
    stream_key: AliasStreamKey,
    nonce: BigUint,
    dest: ChordLocation,
    dest_alias: ChordLocation,
    last_active: Instant,
}

impl AliasEntry {
    pub(crate) fn new(key: ChordPublicKey, stream_key: AliasStreamKey, dest: ChordLocation, dest_alias: ChordLocation) -> Self {
        Self {
            key,
            stream_key,
            nonce: BigUint::ZERO,
            dest,
            dest_alias,
            last_active: Instant::now(),
        }
    }

    /// The key the alias uses to do the encryption
    pub(crate) fn get_key(&self) -> AliasStreamKey {
        self.stream_key
    }

    /// The location where this alias entry lives on the chord
    pub(crate) fn get_location(&self) -> ChordLocation {
        self.key.get_location()
    }

    /// The destination the AliasEntry is aliasing
    pub(crate) fn dest(&self) -> &ChordLocation {
        &self.dest
    }
    pub(crate) fn dest_alias(&self) -> &ChordLocation {
        &self.dest_alias
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
}


#[cfg(test)]
mod tests {


    use rand::random;
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn alias_stream_key_wrap_round_trip() {
        let data: [u8; 10] = random();
        let nonce: AliasNonce = random();
        let mut stream_key = AliasStreamKey::generate();
        
        // wrap
        let transmitted_msg = stream_key.wrap(nonce, &data);
        
        // unwrap
        let recvd_data = stream_key.unwrap(transmitted_msg).expect("message should unwrap");

        // verify
        assert_eq!(data, *recvd_data, "message received is not equal to that sent");
    }

    #[test]
    #[traced_test]
    fn alias_stream_key_wrap_round_trip_failure() {
        let data: [u8; 10] = random();
        let nonce: AliasNonce = random();
        let mut stream_key = AliasStreamKey::generate();
        
        // wrap
        let mut transmitted_msg = stream_key.wrap(nonce, &data);

        // add corruption to message
        transmitted_msg[15] = transmitted_msg[15].wrapping_add(56);
        
        // unwrap
        let recvd_data = stream_key.unwrap(transmitted_msg);
        assert!(recvd_data.is_err(), "corruption should cause the unwrap to fail");
    }

    #[test]
    #[traced_test]
    fn alias_stream_key_wrap_round_trip_nonce_failure() {
        let data: [u8; 10] = random();
        let nonce: AliasNonce = random();
        let mut stream_key = AliasStreamKey::generate();
        
        // wrap
        let mut transmitted_msg = stream_key.wrap(nonce, &data);

        // add corruption to message
        transmitted_msg[5] = transmitted_msg[5].wrapping_add(56);
        
        // unwrap
        let recvd_data = stream_key.unwrap(transmitted_msg);
        assert!(recvd_data.is_err(), "corruption should cause the unwrap to fail");
    }


}
