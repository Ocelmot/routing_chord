
use tokio::{sync::{mpsc::{channel, Receiver, Sender}, oneshot}, task::JoinHandle};
use tracing::trace;

use crate::{
    error::{ChordError, ChordResult, ProblemWrap},
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
    message::{ControlMessage, Message},
};

pub struct ChordHandle {
    key: ChordPublicKey,
    sender: Sender<Message>,
    receiver: Receiver<Vec<u8>>,
    join_handle: JoinHandle<ChordResult>,
}

impl ChordHandle {
    pub(crate) fn new(
        key: ChordPublicKey,
        sender: Sender<Message>,
        receiver: Receiver<Vec<u8>>,
        join_handle: JoinHandle<ChordResult>,
    ) -> Self {
        Self {
            key,
            sender,
            receiver,
            join_handle
        }
    }

    pub fn get_key(&self) -> &ChordPublicKey {
        &self.key
    }

    pub async fn listen_at(&self, at: ChordPrivateKey ) -> ChordResult<Receiver<Vec<u8>>> {
        let (tx, rx) = channel(8);
        self.sender
            .send(Message::Control(ControlMessage::ListenAt(at, tx)))
            .await
            .wrap()?;
            Ok(rx)
    }

    pub async fn connect_to(&self, to: ChordPublicKey, msg: Vec<u8>) -> ChordResult {
        self.sender
            .send(Message::Control(ControlMessage::ConnectTo(to, msg)))
            .await
            .wrap()
    }

    pub async fn recv(&mut self) -> ChordResult<Vec<u8>> {
        self.receiver
            .recv()
            .await
            .ok_or(ChordError::new(crate::error::ErrorKind::ChordStopped))
    }

    pub async fn predecessor(&mut self) -> ChordResult<Option<ChordPublicKey>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Message::Control(ControlMessage::Predecessor(tx))).await.wrap()?;
        rx.await.wrap()
    }

    pub async fn successor(&mut self) -> ChordResult<Option<ChordPublicKey>> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Message::Control(ControlMessage::Successor(tx))).await.wrap()?;
        rx.await.wrap()
    }

    pub async fn get_predecessor<L: Into<ChordLocation>>(&mut self, location: L) -> ChordResult<ChordPublicKey> {
        let (tx, rx) = oneshot::channel();
        self.sender.send(Message::Control(ControlMessage::PredecessorOf(tx, location.into()))).await.wrap()?;
        rx.await.wrap()
    }

    pub async fn debug(&self) -> ChordResult {
        trace!("Sending debug");
        self.sender
            .send(Message::Control(ControlMessage::Debug))
            .await
            .wrap()
    }

    pub fn is_finished(&self) -> bool {
        self.join_handle.is_finished()
    }

    pub async fn get_termination_status(self) -> ChordResult {
        self.join_handle.await.unwrap()
    }
}
