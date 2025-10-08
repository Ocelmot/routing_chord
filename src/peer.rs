use std::{marker::PhantomData, net::{IpAddr, SocketAddr}};

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use num_bigint::BigUint;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, ToSocketAddrs};
use tracing::{error, info};

use crate::{
    error::{ChordError, ChordResult, ErrorKind, ProblemWrap},
    id::{ChordPublicKey, ChordPrivateKey},
    message::{AssociateMessage, MemberMessage},
    protocol::{protocol_wrap_tcp, Protocol, ProtocolReaderStream, ProtocolWriterStream},
};

pub(crate) enum PeerReaderType {
    Member(PeerReader<MemberMessage>),
    Associate(PeerReader<AssociateMessage>),
}

pub(crate) enum PeerWriterType {
    Member(PeerWriter<MemberMessage>),
    Associate(PeerWriter<AssociateMessage>),
}

pub(crate) enum PeerConnectionType {
    Member(PeerReader<MemberMessage>, PeerWriter<MemberMessage>),
    Associate(PeerReader<AssociateMessage>, PeerWriter<AssociateMessage>),
}

impl PeerConnectionType {
    pub(crate) fn split(self) -> (PeerReaderType, PeerWriterType) {
        match self {
            PeerConnectionType::Member(peer_reader, peer_writer) => (
                PeerReaderType::Member(peer_reader),
                PeerWriterType::Member(peer_writer),
            ),
            PeerConnectionType::Associate(peer_reader, peer_writer) => (
                PeerReaderType::Associate(peer_reader),
                PeerWriterType::Associate(peer_writer),
            ),
        }
    }
}

impl Into<(PeerReaderType, PeerWriterType)> for PeerConnectionType {
    fn into(self) -> (PeerReaderType, PeerWriterType) {
        self.split()
    }
}

impl Into<PeerConnectionType> for (PeerReader<MemberMessage>, PeerWriter<MemberMessage>) {
    fn into(self) -> PeerConnectionType {
        PeerConnectionType::Member(self.0, self.1)
    }
}

impl Into<PeerConnectionType> for (PeerReader<AssociateMessage>, PeerWriter<AssociateMessage>) {
    fn into(self) -> PeerConnectionType {
        PeerConnectionType::Associate(self.0, self.1)
    }
}

pub(crate) trait MessageType: Serialize + for<'a> Deserialize<'a> {
    fn is_member() -> bool;
    fn should_encrypt(&self) -> bool;
}

pub(crate) struct PeerReader<MessageType> {
    other_id: ChordPublicKey,
    pub_addr: IpAddr,
    listen_port: u16,
    ps_rx: ProtocolReaderStream,
    other_stream_key: [u8; 32],
    _marker: PhantomData<MessageType>,
}

impl<T: MessageType> PeerReader<T> {
    pub(crate) fn new(
        other_id: ChordPublicKey,
        pub_addr: IpAddr,
        listen_port: u16,
        ps_rx: ProtocolReaderStream,
        other_stream_key: [u8; 32],
    ) -> Self {
        Self {
            other_id,
            pub_addr,
            listen_port,
            ps_rx,
            other_stream_key,
            _marker: PhantomData,
        }
    }

    pub(crate) fn other_id(&self) -> &ChordPublicKey {
        &self.other_id
    }

    pub(crate) fn pub_addr(&self) -> String {
        self.pub_addr.to_string()
    }

    pub(crate) fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.pub_addr, self.listen_port)
    }

    pub(crate) async fn read(&mut self) -> ChordResult<T> {
        Ok(loop {
            let msg = self.ps_rx.recv().await?;
            break match msg {
                Protocol::Introduction { .. } => continue,
                Protocol::StreamInit(_) => continue,
                Protocol::Plaintext(vec) => {
                    let Ok(msg) = bincode::deserialize::<T>(&vec) else {
                        return Err(ChordError::new(ErrorKind::Deserialize));
                    };
                    if msg.should_encrypt() {
                        continue;
                    }
                    msg
                }
                Protocol::Ciphertext(nonce, msg) => {
                    // deserialize/decrypt vec
                    let cipher = ChaCha20Poly1305::new(&self.other_stream_key.into());
                    let nonce_bytes = Nonce::from(nonce);
                    let Ok(plaintext) = cipher.decrypt(&nonce_bytes, msg.as_slice()) else {
                        return Err(ChordError::new(ErrorKind::Deserialize));
                    };
                    let Ok(msg) = bincode::deserialize::<T>(&plaintext) else {
                        return Err(ChordError::new(ErrorKind::Deserialize));
                    };
                    msg
                }
            };
        })
    }
}

#[derive(Debug)]
pub(crate) struct PeerWriter<MessageType> {
    other_id: ChordPublicKey,
    pub_addr: IpAddr,
    listen_port: u16,
    ps_tx: ProtocolWriterStream,
    self_stream_key: [u8; 32],
    nonce: BigUint,
    _phantom: PhantomData<MessageType>,
}

impl<T: MessageType> PeerWriter<T> {
    pub(crate) fn new(other_id: ChordPublicKey, pub_addr: IpAddr, listen_port: u16, ps_tx: ProtocolWriterStream, stream_key: [u8; 32]) -> Self {
        Self {
            other_id,
            pub_addr,
            ps_tx,
            listen_port,
            self_stream_key: stream_key,
            nonce: BigUint::ZERO,
            _phantom: PhantomData,
        }
    }

    pub(crate) fn other_id(&self) -> &ChordPublicKey {
        &self.other_id
    }

    pub(crate) fn pub_addr(&self) -> &IpAddr {
        &self.pub_addr
    }

    pub(crate) fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(self.pub_addr, self.listen_port)
    }

    pub(crate) fn other_addr(&self) -> String {
        self.ps_tx.other_addr()
    }

    pub(crate) async fn write(&mut self, msg: &T) -> ChordResult {
        let serialized_data = bincode::serialize(&msg).wrap()?;
        let proto = if msg.should_encrypt() {
            let mut nonce_bytes = self.nonce.to_bytes_be();
            self.nonce += 1u32;
            nonce_bytes.resize(12, 0);
            let nonce_bytes = TryInto::<[u8; 12]>::try_into(nonce_bytes).unwrap();
            let nonce = Nonce::from(nonce_bytes);

            let cipher = ChaCha20Poly1305::new((&self.self_stream_key).into());

            let encrypted_data = cipher.encrypt(&nonce, serialized_data.as_slice()).unwrap();
            Protocol::Ciphertext(nonce_bytes, encrypted_data)
        } else {
            Protocol::Plaintext(serialized_data)
        };
        self.ps_tx.send(proto).await?;
        Ok(())
    }
}

pub(crate) async fn connect<A: ToSocketAddrs, M: MessageType>(
    priv_id: &ChordPrivateKey,
    addr: A,
    listen_port: u16,
) -> ChordResult<(PeerReader<M>, PeerWriter<M>)> {
    let stream = TcpStream::connect(addr).await.wrap()?;
    let other_addr = stream.peer_addr()?.to_string();
    let (mut ps_rx, mut ps_tx) = protocol_wrap_tcp(stream);

    // send our introduction
    let proto = Protocol::Introduction {
        id: priv_id.get_public_key(),
        pub_addr: other_addr,
        listen_port,
        is_member: M::is_member(),
    };
    ps_tx.send(proto).await?;
    info!("connect sent intro");

    // recv their introduction
    let x = ps_rx.recv().await;
    let Protocol::Introduction {
        id: other_id,
        pub_addr,
        listen_port,
        is_member,
    } = x?
    else {
        error!("Did not receive an introduction");
        return Err(ChordError::new(ErrorKind::FailedToConnect));
    };
    info!("about to parse ipaddr");
    let pub_addr: SocketAddr = pub_addr.parse().wrap()?;
    let pub_addr = pub_addr.ip();


    info!("connect got intro");
    // enforce match of both sides of the stream
    if is_member != M::is_member() {
        error!(
            "Attempted to connect as_member={}, but received is_member={is_member}",
            M::is_member()
        );
        return Err(ChordError::new(ErrorKind::FailedToConnect));
    }

    // send our stream init
    let self_stream_key: [u8; 32] = ChaCha20Poly1305::generate_key(&mut thread_rng()).into();
    let encrypted_key = other_id.encrypt(&self_stream_key)?;
    let proto = Protocol::StreamInit(encrypted_key);
    ps_tx.send(proto).await?;
    info!("connect sent streaminit");

    // recv their stream init
    let x = ps_rx.recv().await;

    let Protocol::StreamInit(encrypted_key) = x? else {
        error!("Connect did not receive a streaminit");
        return Err(ChordError::new(ErrorKind::FailedToConnect));
    };
    info!("connect got streaminit");
    let other_stream_key = priv_id.decrypt(&encrypted_key)?;
    let Ok(other_stream_key) = other_stream_key.try_into() else {
        return Err(ChordError::new(ErrorKind::Deserialize));
    };

    Ok((
        PeerReader::new(other_id.clone(), pub_addr.clone(), listen_port, ps_rx, other_stream_key),
        PeerWriter::new(other_id, pub_addr, listen_port, ps_tx, self_stream_key),
    ))
}

pub(crate) async fn from_listen_stream(
    priv_id: &ChordPrivateKey,
    stream: TcpStream,
    listen_port: u16,
) -> ChordResult<PeerConnectionType> {
    let other_addr = stream.peer_addr()?.to_string();
    let (mut ps_rx, mut ps_tx) = protocol_wrap_tcp(stream);

    // Recv their introduction
    let Protocol::Introduction {
        id: other_id,
        pub_addr,
        listen_port: other_listen_port,
        is_member,
    } = ps_rx.recv().await?
    else {
        return Err(ChordError::new(ErrorKind::FailedToConnect));
    };
    info!("parsing pub_addr from {}", pub_addr);
    let pub_addr: SocketAddr = pub_addr.parse().wrap()?;
    let pub_addr = pub_addr.ip();
    info!("Listener got intro");

    // Send introduction
    let proto = Protocol::Introduction {
        id: priv_id.get_public_key(),
        pub_addr: other_addr,
        listen_port,
        is_member, // mirror their request for if they are a member
    };
    ps_tx.send(proto).await?;
    info!("Listener sent intro");

    // generate stream key
    let self_stream_key: [u8; 32] = ChaCha20Poly1305::generate_key(&mut thread_rng()).into();
    // encrypt with id
    let encrypted_key = other_id.encrypt(&self_stream_key)?;
    // send encrypted stream key
    let proto = Protocol::StreamInit(encrypted_key);
    ps_tx.send(proto).await?;
    info!("Listener sent streaminit");

    // wait for their stream key
    let Protocol::StreamInit(encrypted_key) = ps_rx.recv().await? else {
        return Err(ChordError::new(ErrorKind::FailedToConnect));
    };
    info!("Listener got streaminit");
    let other_stream_key = priv_id.decrypt(&encrypted_key)?;
    let Ok(other_stream_key) = other_stream_key.try_into() else {
        return Err(ChordError::new(ErrorKind::Deserialize));
    };

    Ok(if is_member {
        PeerConnectionType::Member(
            PeerReader::new(other_id.clone(), pub_addr.clone(), other_listen_port, ps_rx, other_stream_key),
            PeerWriter::new(other_id, pub_addr, other_listen_port, ps_tx, self_stream_key),
        )
    } else {
        PeerConnectionType::Associate(
            PeerReader::new(other_id.clone(), pub_addr.clone(), other_listen_port, ps_rx, other_stream_key),
            PeerWriter::new(other_id, pub_addr, other_listen_port, ps_tx, self_stream_key),
        )
    })
}
