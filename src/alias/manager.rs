use std::collections::HashMap;

use tokio::sync::mpsc::Sender;
use tracing::{trace, Span};

use crate::{
    connections::Connections,
    error::{ChordResult, ProblemWrap},
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
    listen_entry::ListenPathEntry,
    message::MemberMessage,
    requests::Requests,
};

use super::{AliasEntry, AliasOperation};

pub(crate) struct Aliases {
    self_id: ChordPrivateKey,

    listen_paths: HashMap<ChordLocation, ListenPathEntry>,
    hosted_aliases: HashMap<ChordLocation, AliasEntry>,

    span: Span,
}

impl Aliases {
    pub(crate) fn new(self_id: ChordPrivateKey, span: &Span) -> Self {
        Self {
            self_id,

            listen_paths: HashMap::new(),
            hosted_aliases: HashMap::new(),

            span: span.clone(),
        }
    }

    pub(crate) fn listen_at(
        &mut self,
        alias_key: ChordPrivateKey,
        host: Option<ChordPublicKey>,
        sender: Sender<Vec<u8>>,
    ) {
        let listen_path_entry = ListenPathEntry::new(alias_key, host, sender);
        self.listen_paths.insert(
            listen_path_entry.dest_key().get_location(),
            listen_path_entry,
        );
    }

    pub(crate) async fn handle_operation(
        &mut self,
        connections: &mut Connections,
        to: ChordPublicKey,
        from: ChordPublicKey,
        op: Vec<u8>,
        sig: Vec<u8>,
    ) {
        if connections.in_controlled_sector(&to) {
            // process
            if to == self.self_id.get_public_key() {
                if from.verify(&op, &sig) {
                    process_operation(from, op, &mut self.hosted_aliases, &self.span).await;
                }
            }
        } else {
            // forward
            connections
                .route_msg(
                    &to.clone(),
                    &MemberMessage::AliasOperation { to, from, op, sig },
                )
                .await;
        }
    }

    pub(crate) async fn process_data(
        &mut self,
        connections: &mut Connections,
        to: ChordLocation,
        alias_id: ChordLocation,
        hop_count: Option<u8>,
        data: Vec<u8>,
    ) -> () {
        if let Some(alias_entry) = self.hosted_aliases.get_mut(&alias_id) {
            trace!("message was in hosted aliases");
            // process hosted alias
            // since we have an entry for this alias, we should wrap the encryption and send it to the new alias direction
            let data = alias_entry.wrap(&data);
            connections
                .route_data(
                    alias_entry.dest().clone(),
                    alias_entry.dest_alias().clone(),
                    None,
                    data,
                )
                .await;
        } else if let Some(entry) = self.listen_paths.get_mut(&alias_id) {
            trace!("message was in listen paths");
            // process incoming data on a listen path
            // since we are the ultimate receiver for this data, we should unwrap the encryption and emit it on the channel
            if let Ok(data) = entry.unwrap(data) {
                trace!("Unwrapped sent data, sending to listener");
                entry.send(data).await;
            } else {
                trace!("Failed to unwrap sent data")
            }
        } else {
            trace!(
                "message was in neither, forwarding from {:#?}, to {:#?}",
                self.self_id.get_location(),
                to
            );
            // forward
            connections.route_data(to, alias_id, hop_count, data).await;
        }
    }

    pub(crate) async fn handle_predecessor_of(
        &mut self,
        connections: &mut Connections,
        requests: &mut Requests,
        of: &ChordLocation,
        key: &ChordPublicKey,
    ) {
        if let Some(entry) = self.listen_paths.get_mut(of) {
            trace!("received response for listen path: key: {:?}", &key);
            entry.set_host(Some(key.clone()));
            let operation = entry.operation_set();
            requests
                .route_alias_op(connections, &key, &self.self_id, operation)
                .await;
        }
    }

    pub(crate) async fn handle_pending(
        &mut self,
        connections: &mut Connections,
        requests: &mut Requests,
    ) {
        // process pending listen connections
        // trace!(parent: &local_span, "Processing pending listen paths");
        for (key, entry) in &mut self.listen_paths {
            if entry.host().is_none() {
                // trace!(parent: &local_span, "Entry was none, requesting predecessor");
                // in upkeep, resend request if missing
                let new_pred = requests
                    .fetch_predecessor_of(connections, key.clone())
                    .await
                    .map(|(key, _)| (key.clone()));
                // trace!(parent: &local_span, "fetch predecessor got {:?}", new_pred);
                entry.set_host(new_pred);
            }
            if let Some(pred) = entry.host() {
                // trace!(parent: &local_span, "Entry was some, sending alias configuration message");
                // in upkeep, send predecessor installation message, if not missing
                let operation = entry.operation_set();
                requests
                    .route_alias_op(connections, pred, &self.self_id, operation)
                    .await;
            }
        }
    }

    // request new alias
    // process alias message
    // etc.
}

async fn process_operation(
    from: ChordPublicKey,
    op: Vec<u8>,
    hosted_aliases: &mut HashMap<ChordLocation, AliasEntry>,
    span: &Span,
) -> ChordResult {
    let operation: AliasOperation = bincode::deserialize(&op).wrap()?;
    match operation {
        AliasOperation::Set {
            inc_key,
            dest_key,
            stream_key,
        } => {
            trace!(parent: span, "AliasOperation: Set");
            // in alias processing, if recv installation message, set up alias if not already set up. Send ping response back through the channel
            hosted_aliases.insert(
                inc_key.get_location(),
                AliasEntry::new(
                    inc_key.clone(),
                    stream_key,
                    from.get_location(),
                    dest_key.get_location(),
                ),
            );
        }
        AliasOperation::Forward(_vec) => todo!(),
    }

    Ok(())
}
