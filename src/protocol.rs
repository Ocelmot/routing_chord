use std::io::{Cursor, Seek};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

use crate::{
    error::{ChordResult, ErrorKind, ProblemWrap},
    id::ChordPublicKey,
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Protocol {
    Introduction { id: ChordPublicKey, pub_addr: String, listen_port: u16, is_member: bool },
    StreamInit(Vec<u8>),
    Plaintext(Vec<u8>),
    Ciphertext([u8; 12], Vec<u8>),
}

pub(crate) fn protocol_wrap_tcp(stream: TcpStream) -> (ProtocolReaderStream, ProtocolWriterStream) {
    let (rx, tx) = stream.into_split();
    (
        ProtocolReaderStream {
            stream: rx,
            buffer: Cursor::new(Vec::new()),
        },
        ProtocolWriterStream { stream: tx },
    )
}

#[derive(Debug)]
pub(crate) struct ProtocolWriterStream {
    stream: OwnedWriteHalf,
}

impl ProtocolWriterStream {
    pub(crate) fn other_addr(&self) -> String {
        self.stream.peer_addr().unwrap().to_string()
    }

    pub(crate) async fn send(&mut self, proto: Protocol) -> ChordResult {
        let data = bincode::serialize(&proto).problem_wrap(ErrorKind::Serialize)?;
        self.stream
            .write_all(&data)
            .await
            .problem_wrap(ErrorKind::SendError)
    }
}

pub(crate) struct ProtocolReaderStream {
    stream: OwnedReadHalf,
    buffer: Cursor<Vec<u8>>,
}

impl ProtocolReaderStream {
    pub(crate) fn other_addr(&self) -> String {
        self.stream.peer_addr().unwrap().to_string()
    }

    pub(crate) async fn recv(&mut self) -> ChordResult<Protocol> {
        let mut buf = [0u8; 1024];
        loop {
            self.buffer.set_position(0);
            match bincode::deserialize_from(&mut self.buffer) {
                Ok(proto) => {
                    // first remove bytes that have been read
                    let read_bytes = self.buffer.position() as usize;
                    self.buffer.get_mut().drain(0..read_bytes);
                    self.buffer.set_position(0);
                    // info!("Yielding {read_bytes} byte message: {:?}", proto);
                    return Ok(proto)
                },
                Err(e) => {
                    if let bincode::ErrorKind::Io(_error) = *e {
                        // trace!("deserialization hit io error: {:?}", _error);
                    } else {
                        return Err(e).problem_wrap(ErrorKind::Deserialize);
                    }
                }
            }

            let read_count = self.stream.read(&mut buf).await?;
            self.buffer.seek(std::io::SeekFrom::End(0)).wrap()?;
            std::io::Write::write_all(&mut self.buffer, &buf[0..read_count]).wrap()?;
            // info!("recv buffer bytes {:?}", self.buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
}
