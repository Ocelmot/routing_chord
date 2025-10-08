use tokio::sync::mpsc::Receiver;

use crate::error::{ChordError, ChordResult, ErrorKind};



pub enum ListenMessage {
    Data(Vec<u8>),
    Ping(u32),
}

pub struct ListenHandler {
    receiver: Receiver<ListenMessage>
}

impl ListenHandler {
    pub(crate) fn new(receiver: Receiver<ListenMessage>) -> Self {
        Self {
            receiver
        }
    }

    pub async fn await_activity(&mut self) -> ChordResult<Option<Vec<u8>>> {
        loop {
            match self.receiver.recv().await.ok_or(ChordError::new(ErrorKind::ListenerHandlerFailed))? {
                ListenMessage::Data(msg) => {
                    return Ok(Some(msg));
                },
                ListenMessage::Ping(_) => {
                    return Ok(None)
                }
            }
        }
    }

    pub async fn recv(&mut self) -> ChordResult<Vec<u8>> {
        loop {
            match self.receiver.recv().await.ok_or(ChordError::new(ErrorKind::ListenerHandlerFailed))? {
                ListenMessage::Data(msg) => {
                    return Ok(msg);
                },
                ListenMessage::Ping(_) => {}
            }
        }
    }
}