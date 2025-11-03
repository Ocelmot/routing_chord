use std::{cmp::Ordering, fmt::Debug};

use num_bigint::BigUint;
use rand::thread_rng;
use rsa::{
    pkcs1v15::{DecryptingKey, Signature, SigningKey, VerifyingKey},
    pkcs8::EncodePublicKey,
    signature::{SignatureEncoding, Signer, Verifier},
    traits::RandomizedDecryptor,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::trace;

use crate::error::{ChordResult, ErrorKind, ProblemWrap};

const KEY_SIZE: usize = 2048;
pub(crate) const LOCATION_BYTE_SIZE: usize = 32;
pub(crate) const LOCATION_BIT_SIZE: u32 = LOCATION_BYTE_SIZE as u32 * 8;

const ENCRYPTION_CHUNK_SIZE: usize = 245;
const ENCRYPTION_RESULT_SIZE: usize = 256;

#[derive(Clone)]
pub struct ChordPrivateKey {
    key: RsaPrivateKey,
}

// ===== Public Key Section =====
impl ChordPrivateKey {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, KEY_SIZE).expect("failed to generate key");
        Self { key }
    }

    pub fn get_public_key(&self) -> ChordPublicKey {
        ChordPublicKey {
            key: self.key.to_public_key(),
        }
    }

    pub fn encrypt(&self, msg: &[u8]) -> ChordResult<Vec<u8>> {
        self.get_public_key().encrypt(msg)
    }

    pub fn encrypt_chunked(&self, msg: &[u8]) -> ChordResult<Vec<u8>> {
        self.get_public_key().encrypt_chunked(msg)
    }

    pub fn decrypt(&self, msg: &[u8]) -> ChordResult<Vec<u8>> {
        let decrypting_key = DecryptingKey::new(self.key.clone());
        decrypting_key
            .decrypt_with_rng(&mut thread_rng(), msg)
            .wrap()
    }

    pub fn decrypt_chunked(&self, msg: &[u8]) -> ChordResult<Vec<u8>> {
        let decrypting_key = DecryptingKey::new(self.key.clone());
        let mut result = Vec::new();
        for chunk in msg.chunks(ENCRYPTION_RESULT_SIZE) {
            let decrypted = decrypting_key
                .decrypt_with_rng(&mut thread_rng(), chunk)
                .wrap()?;
            result.extend_from_slice(&decrypted);
        }
        Ok(result)
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 256] {
        let signing_key = SigningKey::<Sha256>::new(self.key.clone());
        let sig = signing_key.sign(data).to_bytes();
        sig.as_ref().try_into().unwrap()
    }

    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        self.get_public_key().verify(data, sig)
    }

    pub fn get_location(&self) -> ChordLocation {
        self.get_public_key().get_location()
    }
}

impl Debug for ChordPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PRIV:{:#?}", self.get_location())
    }
}

// ===== Chord Public Key =====

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChordPublicKey {
    key: RsaPublicKey,
}

impl ChordPublicKey {
    pub fn get_location(&self) -> ChordLocation {
        ChordLocation {
            num: BigUint::from_bytes_be(&self.sha256()),
        }
    }
    // Crypto functions
    pub fn sha256(&self) -> [u8; 32] {
        let document = self
            .key
            .to_public_key_der()
            .problem_wrap(ErrorKind::Serialize)
            .unwrap();
        let mut hasher = Sha256::new();
        hasher.update(document.as_bytes());
        hasher.finalize().into()
    }

    pub fn as_pub_key(&self) -> &RsaPublicKey {
        &self.key
    }

    pub fn encrypt(&self, msg: &[u8]) -> ChordResult<Vec<u8>> {
        self.key
            .encrypt(&mut thread_rng(), Pkcs1v15Encrypt, msg)
            .wrap()
    }

    pub fn encrypt_chunked(&self, msg: &[u8]) -> ChordResult<Vec<u8>> {
        let mut result = Vec::new();
        for chunk in msg.chunks(ENCRYPTION_CHUNK_SIZE) {
            let encrypted = self.key
                .encrypt(&mut thread_rng(), Pkcs1v15Encrypt, chunk)
                .wrap()?;

            result.extend_from_slice(&encrypted);
        }

        Ok(result)
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let verifying_key = VerifyingKey::<Sha256>::new(self.key.clone());
        match Signature::try_from(sig) {
            Ok(sig) => verifying_key.verify(msg, &sig).is_ok(),
            Err(_) => false,
        }
    }
}
impl PartialOrd for ChordPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ChordPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_location().cmp(&other.get_location())
    }
}

impl Debug for ChordPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PUB:{:#?}", self.get_location())
    }
}

// ===== ChordLocation =====

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChordLocation {
    num: BigUint,
}

impl ChordLocation {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.num.to_bytes_be()
    }

    fn wrap_point() -> Self {
        Self {
            num: BigUint::from_bytes_be(&[0xff; LOCATION_BYTE_SIZE]),
        }
    }

    /// calculate the id of the finger at the given index
    pub fn calculate_finger(&self, mut index: u32) -> Self {
        index = index.clamp(1, LOCATION_BIT_SIZE);
        let mut big_num = self.num.clone();
        let offset = BigUint::new(vec![2]).pow(index - 1);
        big_num += offset;
        big_num = big_num % Self::wrap_point().num;
        Self { num: big_num }
    }

    /// Calculate the next finger index from the current one
    pub fn next_index(prev_index: u32) -> u32 {
        let mut next_index = prev_index + 1;
        if next_index > LOCATION_BIT_SIZE {
            next_index = 1;
        }
        next_index.clamp(1, LOCATION_BIT_SIZE)
    }

    /// Determines if this ChordLocation falls within the range [start, end).
    pub fn is_in_half_open_sector<S, E>(&self, start: S, end: E) -> bool
    where
        S: Into<ChordLocation>,
        E: Into<ChordLocation>,
    {
        let start = start.into();
        let end = end.into();

        match start.cmp(&end) {
            Ordering::Less => {
                // The sector does not overlap the wrap point
                *self >= start && *self < end
            }
            Ordering::Equal => {
                // The sector is only a single element
                *self == start
            }
            Ordering::Greater => {
                // the sector overlaps the wrap point
                *self >= start || *self < end
            }
        }
    }

    /// Determines if this ChordLocation falls within the range (start, end).
    pub fn is_in_open_sector<S, E>(&self, start: S, end: E) -> bool
    where
        S: Into<ChordLocation>,
        E: Into<ChordLocation>,
    {
        let start = start.into();
        let end = end.into();

        match start.cmp(&end) {
            Ordering::Less => {
                // The sector does not overlap the wrap point
                *self > start && *self < end
            }
            Ordering::Equal => {
                // The sector is only a single element
                false
            }
            Ordering::Greater => {
                // the sector overlaps the wrap point
                *self > start || *self < end
            }
        }
    }
}

impl From<&[u8; LOCATION_BYTE_SIZE]> for ChordLocation {
    fn from(value: &[u8; LOCATION_BYTE_SIZE]) -> Self {
        Self {
            num: BigUint::from_bytes_be(value),
        }
    }
}

impl From<&ChordPrivateKey> for ChordLocation {
    fn from(value: &ChordPrivateKey) -> Self {
        value.get_location()
    }
}

impl From<&ChordPublicKey> for ChordLocation {
    fn from(value: &ChordPublicKey) -> Self {
        value.get_location()
    }
}

impl std::fmt::Debug for ChordLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let width = f.width().unwrap_or(3);
        if !f.alternate() {
            write!(f, "LOC:")?;
        }
        if width <= self.num.to_bytes_be().len()  {
            for byte in &self.num.to_bytes_be()[0..width] {
                write!(f, "{:02X?}", byte)?;
            }
        }else{
            for byte in self.num.to_bytes_be() {
                write!(f, "{:02X?}", byte)?;
            }
            for _ in 0..width - self.num.to_bytes_be().len(){
                write!(f, " ")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use rand::random;

    use super::*;

    #[test]
    #[test_log::test]
    fn signature_round_trip() {
        let data: [u8; 10] = random();
        let id = ChordPrivateKey::generate();

        // sign
        let signature = id.sign(&data);

        // verify
        assert!(id.get_public_key().verify(&data, &signature));
    }

    #[test]
    #[test_log::test]
    fn signature_failure() {
        let data: [u8; 10] = random();
        let id = ChordPrivateKey::generate();

        // sign
        let mut signature = id.sign(&data);
        // corrupt byte
        signature[2] = random();

        // verify
        assert!(!id.get_public_key().verify(&data, &signature));
    }

    #[test]
    #[test_log::test]
    fn signature_data_change() {
        let mut data: [u8; 10] = random();
        let id = ChordPrivateKey::generate();

        // sign
        let signature = id.sign(&data);
        // corrupt byte
        let mut corruption = random();
        while data[2] == corruption {
            corruption = random();
        }
        data[2] = corruption;

        // verify
        assert!(!id.get_public_key().verify(&data, &signature));
    }

    #[test]
    #[test_log::test]
    fn enc_round_trip_rand() {
        let data = {
            (0..1000).map(|_|random::<u8>()).collect::<Vec<_>>()
        };
        let id = ChordPrivateKey::generate();

        // encrypt
        let enc = id.get_public_key().encrypt_chunked(&data).expect("message failed to encrypt");

        // decrypt
        let dec = id.decrypt_chunked(&enc).expect("message failed to decrypt");

        // Assert round trip
        assert!(data == dec);
    }

    
    #[test]
    #[test_log::test]
    fn enc_round_trip_ff() {
        let data = {
            (0..1000).map(|_|0xffu8).collect::<Vec<_>>()
        };
        let id = ChordPrivateKey::generate();

        // encrypt
        let enc = id.get_public_key().encrypt_chunked(&data).expect("message failed to encrypt");

        // decrypt
        let dec = id.decrypt_chunked(&enc).expect("message failed to decrypt");

        // Assert round trip
        assert!(data == dec);
    }

    #[test]
    #[test_log::test]
    fn enc_data_change() {
        let data = {
            (0..1000).map(|_|random::<u8>()).collect::<Vec<_>>()
        };
        let id = ChordPrivateKey::generate();

        // encrypt
        let mut enc = id.get_public_key().encrypt_chunked(&data).expect("message failed to encrypt");

        // corrupt byte
        let index = random::<usize>() % enc.len();
        let mut corruption = random();
        while enc[index] == corruption {
            corruption = random();
        }
        enc[index] = corruption;

        // decrypt should fail
        assert!(id.decrypt_chunked(&enc).is_err());

    }
}
