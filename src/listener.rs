use std::{error::Error, net::SocketAddr};

use tokio::{net::TcpStream, sync::mpsc::Sender};
use tracing::{error, trace};

use crate::{
    error::{ChordError, ChordResult, ErrorKind, ProblemWrap},
    id::ChordPrivateKey,
    message::{ControlMessage, Message},
    peer::{from_listen_stream, PeerConnectionType, PeerReaderType, PeerWriterType},
};

pub(crate) fn listen_handler(
    priv_id: ChordPrivateKey,
    sender: &Sender<Message>,
    stream: TcpStream,
    addr: SocketAddr,
    listen_port: u16,
) {
    let task_sender = sender.clone();

    // Task to determine what kind of connection is incoming and create the appropriate type
    tokio::spawn(async move {
        match from_listen_stream(&priv_id, stream, listen_port).await {
            Ok(connection) => {
                process_connection_type(task_sender, connection);
                ChordResult::Ok(())
            },
            Err(e) => {
                error!("from_listen_stream failed: {}", e);
                Err(e)
            },
        }
    });
}

pub(crate) fn process_connection_type<C>(sender: Sender<Message>, connection_type: C)
where
    C: Into<PeerConnectionType> + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let (mut reader, writer) = connection_type.into().split();
        let ctrl_msg = match writer {
            PeerWriterType::Member(writer) => ControlMessage::AddMember(writer),
            PeerWriterType::Associate(writer) => ControlMessage::AddAssociate(writer),
        };
        trace!("process_connection_type sending {:?}", ctrl_msg);

        sender
            .send(Message::Control(ctrl_msg))
            .await
            .problem_wrap(ErrorKind::ChordStopped).expect("Sender channel should be open when chord is running");

        trace!("process_connection_type looping");
        // loop to recv messages
        loop {
            let msg = match &mut reader {
                PeerReaderType::Member(reader) => {
                    let msg = reader.read().await?;
                    Message::Member(reader.other_id().clone(), msg)
                }
                PeerReaderType::Associate(reader) => {
                    let msg = reader.read().await?;
                    Message::Associate(reader.other_id().clone(), msg)
                }
            };

            sender
                .send(msg)
                .await
                .problem_wrap(ErrorKind::ChordStopped)?;
        }
        #[allow(unreachable_code)]
        ChordResult::Ok(())
    });
}

async fn process_message(
    reader: &mut PeerReaderType,
    task_sender: &Sender<Message>,
) -> Result<(), ChordError> {
    let msg = match reader {
        PeerReaderType::Member(reader) => {
            let msg = reader.read().await?;
            Message::Member(reader.other_id().clone(), msg)
        }
        PeerReaderType::Associate(reader) => {
            let msg = reader.read().await?;
            Message::Associate(reader.other_id().clone(), msg)
        }
    };

    task_sender
        .send(msg)
        .await
        .problem_wrap(ErrorKind::ChordStopped)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::{net::TcpListener, sync::mpsc::channel};
    use tracing::info;
    use tracing_test::traced_test;

    use crate::{
        message::{AssociateMessage, MemberMessage},
        peer::connect,
    };

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn member_round_trip() {
        let ip_addr = "127.0.0.1:6000";
        let conn_priv_id = ChordPrivateKey::generate();
        let task_conn_id = conn_priv_id.get_public_key();
        // start listener
        tokio::spawn(async move {
            info!("Listen task spawned");
            let listener = TcpListener::bind(ip_addr).await.unwrap();
            let (stream, addr) = listener.accept().await.unwrap();
            info!("listener accepted a socket");
            let priv_id = ChordPrivateKey::generate();
            let (sender, mut receiver) = channel(5);
            listen_handler(priv_id, &sender, stream, addr, 6000);
            info!("listen_handler completed");

            // wait for incoming messages to the listener
            let Message::Control(ControlMessage::AddMember(mut member_writer)) =
                receiver.recv().await.unwrap()
            else {
                panic!("Should have received a member over the listen channel");
            };

            // Read member message
            let Message::Member(id, msg) = receiver.recv().await.unwrap() else {
                panic!("Should receive a member message");
            };
            info!("Got member message");
            assert_eq!(id, task_conn_id);
            assert_eq!(msg, MemberMessage::Notify);

            // Send member message
            info!("sending notify to connector");
            member_writer.write(&MemberMessage::Notify).await.unwrap();
            info!("Listen task completed")
        });

        // connect/send message

        let (mut conn_reader, mut conn_writer) = connect(&conn_priv_id, ip_addr, 0).await.unwrap();
        info!("Connected to listener");

        conn_writer.write(&MemberMessage::Notify).await.unwrap();
        info!("Sent notify");

        // Read member message
        let MemberMessage::Notify = conn_reader.read().await.unwrap() else {
            panic!("Should receive a notify in return");
        };
        info!("connection completed")
    }

    #[tokio::test]
    #[traced_test]
    async fn associate_round_trip() {
        let ip_addr = "127.0.0.1:6001";
        let conn_priv_id = ChordPrivateKey::generate();
        let task_conn_id = conn_priv_id.get_public_key();
        // start listener
        tokio::spawn(async move {
            info!("Listen task spawned");
            let listener = TcpListener::bind(ip_addr).await.unwrap();
            let (stream, addr) = listener.accept().await.unwrap();
            info!("listener accepted a socket");
            let priv_id = ChordPrivateKey::generate();
            let (sender, mut receiver) = channel(5);
            listen_handler(priv_id, &sender, stream, addr, 6001);
            info!("listen_handler completed");

            // wait for incoming messages to the listener
            let Message::Control(ControlMessage::AddAssociate(mut associate_writer)) =
                receiver.recv().await.unwrap()
            else {
                panic!("Should have received an associate over the listen channel");
            };

            // Read member message
            let Message::Associate(id, msg) = receiver.recv().await.unwrap() else {
                panic!("Should receive a member message");
            };
            info!("Got associate message");
            assert_eq!(id, task_conn_id);
            assert_eq!(msg, AssociateMessage::Ping);

            // Send member message
            info!("sending notify to connector");
            associate_writer
                .write(&AssociateMessage::Ping)
                .await
                .unwrap();
            info!("Listen task completed")
        });

        // connect/send message

        let (mut conn_reader, mut conn_writer) = connect(&conn_priv_id, ip_addr, 0).await.unwrap();
        info!("Connected to listener");

        conn_writer.write(&AssociateMessage::Ping).await.unwrap();
        info!("Sent notify");

        // Read member message
        if conn_reader.read().await.is_err() {
            panic!("Should receive a notify in return");
        }
        info!("connection completed")
    }
}
