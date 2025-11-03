use std::{
    collections::HashMap,
    error::Error,
    iter::{once, Once},
    time::{Duration, Instant},
};

use serde::Deserialize;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, trace, warn, Instrument, Span};

use crate::{
    alias::{self, AliasId, AliasResponse, AliasStreamKey},
    connections::Connections,
    error::{ChordError, ChordResult, ErrorKind, ProblemWrap},
    id::{ChordLocation, ChordPrivateKey, ChordPublicKey},
    message::MemberMessage,
    requests::Requests,
};

use super::{
    listen_path::{ListenPath, ListenPathEntry},
    AliasOperation, HostedAliasEntry,
};

const ENTRY_PING: Duration = Duration::from_secs(30);
const ENTRY_TIMEOUT: Duration = Duration::from_secs(60000);

pub(crate) const DEFAULT_LISTEN_PATH_LENGTH: usize = 3;

pub(crate) struct Aliases {
    self_id: ChordPrivateKey,

    /// Map of incoming Alias locations to possible listen paths
    listen_paths: HashMap<ChordLocation, ListenPath>,

    /// Aliases this node is hosting. Mapped from the location of its key to its entry
    hosted_aliases: HashMap<ChordLocation, HostedAliasEntry>,

    /// Table of incoming addresses, calculated from outgoing forwarded messages.
    ///
    /// Maps previous forwarded destinations to the alias location
    forwarded_addrs: HashMap<ChordLocation, ChordLocation>,

    /// entries that do not yet have a host, they are waiting
    /// for the predecessor of their location to reply.
    ///
    /// Map from the alias location, to (<Id of path that needs the data>)
    pending_remote_aliases: HashMap<ChordLocation, ChordLocation>,

    // Pending requests for a hosted alias's pred request
    alias_pred_requests: HashMap<ChordLocation, Vec<ChordLocation>>,

    // This node's debug logging span
    span: Span,
}

impl Aliases {
    pub(crate) fn new(self_id: ChordPrivateKey, span: &Span) -> Self {
        Self {
            self_id,

            listen_paths: HashMap::new(),
            hosted_aliases: HashMap::new(),
            forwarded_addrs: HashMap::new(),
            pending_remote_aliases: HashMap::new(),
            alias_pred_requests: HashMap::new(),

            span: span.clone(),
        }
    }

    pub(crate) async fn listen_at(
        &mut self,
        connections: &mut Connections,
        requests: &mut Requests,
        listen_key: ChordPrivateKey,
        sender: Sender<Vec<u8>>,
        length: usize,
    ) {
        trace!(parent: &self.span, "Generating listen path (prints from closest to furthest)");
        let mut listen_path = ListenPath::new(listen_key, sender, length);

        for entry in listen_path.entries() {
            trace!(parent: &self.span, "path entry at {:?}", entry.key().get_location());
        }

        let path_loc = listen_path.path_loc();

        let entry = listen_path.entries_mut().next().unwrap();

        let pred = self
            .request_create_alias(
                connections,
                requests,
                &entry.key().get_public_key(),
                self.self_id.get_public_key(),
                path_loc,
                *entry.stream_key(),
            )
            .await;

        // If there was a pred, assign the pred
        entry.set_host(pred);

        self.listen_paths
            .insert(listen_path.path_loc(), listen_path);
    }

    /// Requests for an alias to be hosted. This could be at this node, or it
    /// could be at some other node.
    ///
    /// This will send a message getting the predecessor
    pub(crate) async fn request_create_alias(
        &mut self,
        connections: &mut Connections,
        requests: &mut Requests,
        alias_key: &ChordPublicKey,
        alias_dest: ChordPublicKey,
        path_loc: ChordLocation,
        alias_stream_key: AliasStreamKey,
    ) -> Option<ChordPublicKey> {
        // get pred, if we have it add the full entry and signal ready.
        // if there is no entry, add to pending, and send request for pred
        let pred = requests
            .fetch_predecessor_of(connections, alias_key.get_location())
            .await;
        match pred {
            Some((pred, _addr)) => {
                trace!(parent: &self.span, "Got predecessor of alias immediately = {:?}", pred.get_location());

                if self.self_id.get_public_key() == *pred {
                    info!(parent: &self.span, "Pred of alias is in our sector");
                    // if pred is us, self host
                    let hosted_entry = HostedAliasEntry::new(
                        alias_key.clone(),
                        alias_dest.clone(),
                        alias_stream_key,
                    );
                    self.hosted_aliases
                        .insert(alias_key.get_location(), hosted_entry);
                    // since the host is set up, send a message back to this node that it is ok
                    let data = AliasResponse::Established
                        .serialize_encrypt(&alias_key)
                        .ok()?;

                    connections.send_self(MemberMessage::AliasResponse {
                        to: alias_dest.get_location(),
                        from: alias_key.get_location(),
                        // sig: sig.to_vec(),
                        data,
                    });
                } else {
                    // otherwise send set message
                    info!(parent: &self.span, "Pred of alias is in another sector");
                    let op = AliasOperation::Set {
                        alias_key: alias_key.clone(),
                        stream_key: alias_stream_key,
                    };
                    let _ = connections
                        .route_alias_op(pred.into(), &self.self_id, op)
                        .await;
                    // In this case the other node will send an ok message back.
                }
                Some(pred.clone())
            }
            None => {
                // Enter into pending alias list. This will insert later
                info!(parent: &self.span, "Pred of alias is pending a reply");
                self.pending_remote_aliases
                    .insert(alias_key.get_location(), path_loc);
                None
            }
        }
    }

    /// We have received an Alias operation from the chord, either process it or forward
    pub(crate) async fn handle_operation(
        &mut self,
        connections: &mut Connections,
        requests: &mut Requests,
        to: ChordLocation,
        from: ChordPublicKey,
        op: Vec<u8>,
        sig: Vec<u8>,
    ) {
        trace!(parent: &self.span, "Handling AliasOperation from {:?}", from.get_location());
        if connections.in_controlled_sector(to.clone()) {
            // process
            trace!(parent: &self.span, "Alias is in sector");

            if from.verify(&op, &sig) {
                let result = process_operation(
                    connections,
                    requests,
                    to,
                    from,
                    op,
                    &mut self.hosted_aliases,
                    &mut self.alias_pred_requests,
                    &mut self.forwarded_addrs,
                    &self.span,
                )
                .await;
                trace!(parent: &self.span, "Result of processing alias operation: {:?}", result);
            } else {
                trace!(parent: &self.span, "Failed to verify")
            }
        } else {
            // forward
            trace!(parent: &self.span, "forwarding alias operation from {:?} to {:?}", from.get_location(), to.clone());
            connections
                .route_msg(
                    to.clone(),
                    &MemberMessage::AliasOperation { to, from, op, sig },
                )
                .await;
        }
    }

    pub(crate) async fn handle_response(
        &mut self,
        connections: &mut Connections,
        to: ChordLocation,
        from: ChordLocation,
        mut data: Vec<u8>,
    ) -> ChordResult {
        let span = self.span.clone();
        trace!(parent: &span, "Handling alias response from {:?}, to {:?}", from, to);

        if let Some(listen_path) = self.listen_paths.get_mut(&from) {
            // check alias paths
            trace!(parent: &span, "Got Alias Path");

            // Unwrap the response. then handle the response
            // Responses are wrapped with each successive alias key
            let mut about = listen_path.first_entry().key();
            let mut response = None;
            for entry in listen_path.entries() {
                let decrypted = AliasResponse::decrypt_deserialize(entry.key(), &data)?;

                match decrypted {
                    AliasResponse::Wrapped(inner) => {
                        // trace!(parent: &span, "Unwrapping response");
                        data = inner;
                    }
                    _ => {
                        response = Some(decrypted);
                        about = entry.key();
                        break;
                    } // message has been fully unwrapped
                }
                about = entry.key();
            }

            let Some(response) = response else {
                warn!("Message wrapped too much");
                return Ok(());
            };
            trace!(parent: &span, "Processing {}", &response);

            trace!(parent: &span, "response is from alias at {:?}", about.get_location());
            if let Some((_head, entry, mut tail)) = listen_path.get_segments(about.get_location()) {
                trace!(parent: &span, "Got path segments");
                // verify the sig came from this entry's host

                match response {
                    AliasResponse::Established => {
                        trace!(parent: &span, "Response is Established");
                        entry.last_active();

                        if let Some(next) = tail.iter().next() {
                            // alias established, get pred of next segment to extend
                            trace!("Establishing next link in path");
                            let location = entry.location();

                            let msg = AliasOperation::GetPred(entry.key().get_public_key(), next.key().get_location());
                            listen_path.send_to(connections, location, msg).await?;
                        } else {// else: the connection is fully established
                            trace!("Path is fully established");
                        }
                    }
                    AliasResponse::Alive => {
                        trace!(parent: &span, "Response is Alive");
                        entry.active_now();
                    }
                    AliasResponse::Pred { pred, of } => {
                        trace!(parent: &span, "Response is Pred");
                        // we have received the predecessor of a host.
                        // find the entry, update the host, send the alias set request.

                        // if there is no next node, there should not have been a request
                        let Some(next) = tail.iter_mut().next() else {
                            return Ok(());
                        };

                        // Check that the response is for this node
                        if next.key().get_location() != of {
                            return Ok(());
                        }

                        // assign the newly learned host
                        next.set_host(Some(pred.clone()));

                        // start the next phase of establishing a connection
                        let msg = AliasOperation::Set {
                            alias_key: next.key().get_public_key(),
                            stream_key: *next.stream_key(),
                        };

                        let location = next.location();

                        trace!(parent: &span, "Sending {:?} to {:?}", msg, location);
                        let _ = listen_path.send_to(connections, location, msg).await;
                    }
                    AliasResponse::Stopped => todo!("regenerate this entry to patch the chain (have to fix the node after as well)"),
                    AliasResponse::Wrapped(_) => {
                        trace!("AliasResponse should have been fully unwrapped previously");
                    }
                }
                Ok(())
            } else {
                trace!(parent: &span, "failed to get segments");
                Ok(())
            }
        } else {
            // get the alias id to continue the response down the path.
            // Either from the forwarded addrs' alias addr, or from the to addr directly
            let hosted_alias = self
                .forwarded_addrs
                .get(&from)
                .map(|alias_addr| self.hosted_aliases.get(alias_addr))
                .flatten()
                .or_else(|| self.hosted_aliases.get(&to));

            if let Some(hosted_alias) = hosted_alias {
                // Check hosted aliases. Since all aliases send to their target
                // directly, the from value is used to find the hosted alias. This
                // differs from how data is sent, since data could be sent to the
                // alias instead of the host.
                let span = hosted_alias.span(Some(&span));
                let _enter = span.enter();

                // forward response along the path
                trace!(
                    "Wrapping alias old from {:?} new from {:?}",
                    from,
                    hosted_alias.alias_key().get_location()
                );

                // wrap data with alias key
                let data =
                    AliasResponse::Wrapped(data).serialize_encrypt(hosted_alias.alias_key())?;

                let msg = MemberMessage::AliasResponse {
                    to: hosted_alias.dest_key().get_location(),
                    from: hosted_alias.alias_key().get_location(),
                    data,
                };

                drop(_enter);
                if *hosted_alias.dest_key() == self.self_id.get_public_key() {
                    span.in_scope(|| connections.send_self(msg));
                    Ok(())
                } else {
                    connections
                        .route_msg(hosted_alias.dest_key().get_location(), &msg)
                        .instrument(span)
                        .await;
                    Ok(())
                }
            } else {
                debug!("Could not find alias for {:?}", to);
                Ok(())
            }
        }
    }

    pub(crate) async fn process_data(
        &mut self,
        connections: &mut Connections,
        to: ChordLocation,
        alias_loc: ChordLocation,
        hop_count: Option<u8>,
        data: Vec<u8>,
    ) -> () {
        if let Some(entry) = self.listen_paths.get_mut(&alias_loc) {
            trace!("message was in listen paths");
            // process incoming data on a listen path
            // since we are the ultimate receiver for this data, we should unwrap the encryption and emit it on the channel
            if let Ok(data) = entry.unwrap(data) {
                trace!("Unwrapped sent data, sending to listener");
                let _ = entry.sender().send(data).await;
            } else {
                trace!("Failed to unwrap sent data")
            }
        } else {
            // get the alias id to continue the response down the path.
            // Either from the forwarded addrs' alias addr, or from the to addr directly
            let mut hosted_alias = self
                .forwarded_addrs
                .get_mut(&alias_loc)
                .map(|alias_addr| self.hosted_aliases.get_mut(alias_addr))
                .flatten();
            if hosted_alias.is_none() {
                hosted_alias = self.hosted_aliases.get_mut(&to);
            }

            if let Some(hosted_alias) = hosted_alias {
                // enter alias's span
                let span = hosted_alias.span(Some(&self.span));
                let _enter = span.enter();

                trace!(
                    "message was in hosted aliases, {:?} => {:?}",
                    hosted_alias.alias_key(),
                    hosted_alias.dest_key()
                );
                // process hosted alias
                // since we have an entry for this alias, we should wrap the encryption and send it to the new alias direction
                let data = hosted_alias.wrap(&data);
                connections
                    .route_data(
                        hosted_alias.dest_key().get_location(),
                        hosted_alias.alias_key().get_location(),
                        None,
                        data,
                    )
                    .await;
            } else {
                // No path or host was found, forward along msg
                trace!(
                    "no listen path or hosted alias, forwarding from {:#?}, to {:#?}, with hop count of {:?}",
                    self.self_id.get_location(),
                    to.clone(),
                    hop_count
                );
                connections.route_data(to, alias_loc, hop_count, data).await;
            }
        }
    }

    /// When the node receives a predecessor of message, it could be because a listen_path needs a host.
    pub(crate) async fn handle_predecessor_of(
        &mut self,
        connections: &mut Connections,
        of: &ChordLocation,
        pred: &ChordPublicKey,
    ) -> ChordResult {
        let span = self.span.clone();
        trace!(parent: &span, "Alias processing predecessor {:?} of {:?}", pred.get_location(), of);

        // Received a predecessor of a pending remote alias.
        // The node can now create the full host, and signal its complete
        if let Some(path_loc) = self.pending_remote_aliases.remove(of) {
            trace!("received pred for pending remote host: {:?}", &path_loc);

            // The thing here is that a remote host needs to host our alias, but we don't know which one.
            // Since we have the pred response of the alias's key, we can now send the set request.

            if let Some(listen_path) = self.listen_paths.get_mut(&path_loc) {
                trace!("got listen path for pending remote host: {:?}", &path_loc);
                // Set the newly-learned predecessor to the appropriate listen path entry.
                if let Some(entry) = listen_path.get_entry(of.clone()) {
                    trace!("found entry for pending remote host: {:?}", &path_loc);
                    entry.set_host(Some(pred.clone()));

                    // Now, send the AliasOperation::Set instruction to the location
                    let msg = AliasOperation::Set {
                        alias_key: entry.key().get_public_key(),
                        stream_key: *entry.stream_key(),
                    };
                    // let to = entry.host().expect("host was just set").get_location();
                    let to = entry.location();
                    listen_path.send_to(connections, to, msg).await?;
                }
            } else {
                trace!(parent: &span, "no listen path for received pred");
            }
        }

        // Received predecessor of alias pred request
        if let Some(requesting) = self.alias_pred_requests.remove(of) {
            trace!(parent: &span, "found alias pred request, responding");
            for requester in requesting {
                if let Some(hosted_alias) = self.hosted_aliases.get(&requester) {
                    trace!(parent: &span, "Sending Pred to dest {:?}", hosted_alias.dest_key().get_location());
                    let data = AliasResponse::Pred {
                        pred: pred.clone(),
                        of: of.clone(),
                    }
                    .serialize_encrypt(hosted_alias.alias_key())?;

                    let msg = MemberMessage::AliasResponse {
                        to: hosted_alias.dest_key().get_location(),
                        from: hosted_alias.alias_key().get_location(),
                        data: data.to_vec(),
                    };
                    if hosted_alias.dest_key().get_location()
                        == connections.self_id().get_location()
                    {
                        connections.send_self(msg);
                    } else {
                        connections
                            .route_msg(hosted_alias.dest_key().get_location(), &msg)
                            .await;
                    }
                }
            }
        }
        Ok(())
    }

    /// Every so ofter the aliases must be checked for consistency and cleaned up/refreshed
    pub(crate) async fn handle_pending(
        &mut self,
        connections: &mut Connections,
        requests: &mut Requests,
    ) -> ChordResult {
        // Advance listen path entries that are not yet established.
        for (_alias_id, listen_path) in &mut self.listen_paths {
            let mut prev_entry = None::<&ListenPathEntry>;
            for entry in listen_path.entries() {
                if entry.host().is_none() {
                    // there is no host, resend pred request
                    if let Some(prev_entry) = prev_entry {
                        let msg = AliasOperation::GetPred(
                            prev_entry.key().get_public_key(),
                            entry.location(),
                        );
                        listen_path
                            .send_to(connections, prev_entry.location(), msg)
                            .await?;
                    } else {
                        requests
                            .fetch_predecessor_of(connections, entry.location())
                            .await;
                    }
                    break; // further nodes are unreachable
                }
                match entry.last_active() {
                    None => {
                        // there is no last active, resend set
                        let msg = AliasOperation::Set {
                            alias_key: entry.key().get_public_key(),
                            stream_key: *entry.stream_key(),
                        };
                        listen_path
                            .send_to(connections, entry.location(), msg)
                            .await?;
                        break; // if an entry is not established, the later entries do not matter
                    }
                    Some(last_active) if *last_active < Instant::now() - ENTRY_PING => {
                        // If an entry is established, but it has been a while, send ping.
                        let msg = AliasOperation::Ping(entry.key().get_public_key());
                        listen_path
                            .send_to(connections, entry.key().get_location(), msg)
                            .await?;
                    }
                    Some(last_active) if *last_active < Instant::now() - ENTRY_TIMEOUT => {
                        // If an entry is established, but it has been too long, regenerate the entry.
                        todo!("timed out, should regen entry. Requires the prev node and to be able to mutate the current node.");
                        break; // if a node is not responding, the later nodes will be unreachable
                    }
                    // A normal amount of time, do nothing
                    Some(_) => {}
                }
                prev_entry = Some(entry);
            }
        }
        Ok(())
    }
}

// We have received an AliasOperation from the chord, for this node
async fn process_operation(
    connections: &mut Connections,
    requests: &mut Requests,
    to: ChordLocation,
    from: ChordPublicKey,
    op: Vec<u8>,
    hosted_aliases: &mut HashMap<ChordLocation, HostedAliasEntry>,
    alias_pred_requests: &mut HashMap<ChordLocation, Vec<ChordLocation>>,
    forwarded_addrs: &mut HashMap<ChordLocation, ChordLocation>,
    span: &Span,
) -> ChordResult {
    trace!(parent: span, "Decrypting with {:?}", connections.self_id().get_location());

    let bytes = connections.self_id().decrypt_chunked(&op)?;
    let operation = AliasOperation::deserialize(&bytes)?;

    trace!(parent: span, "Processing alias operation {:?}", operation);
    match operation {
        // We have been requested to host an alias with the following details
        AliasOperation::Set {
            alias_key,
            stream_key,
        } => {
            trace!(parent: span, "AliasOperation: Set alias at {:?} to {:?}", alias_key, from);
            // in alias processing, if recv installation message, set up alias if not already set up. Send ping response back through the channel
            let alias_loc = alias_key.get_location();
            let alias_key_2 = alias_key.clone();
            hosted_aliases.insert(
                alias_loc.clone(),
                HostedAliasEntry::new(alias_key, from.clone(), stream_key),
            );

            // return established message
            let data = AliasResponse::Established.serialize_encrypt(&alias_key_2)?;
            let msg = MemberMessage::AliasResponse {
                to: from.get_location(),
                from: alias_loc,
                data,
            };
            if from == connections.self_id().get_public_key() {
                connections.send_self(msg);
            } else {
                connections.route_msg(from.get_location(), &msg).await;
            }
        }

        AliasOperation::GetPred(alias_key, of) => {
            // Check that we actually host the alias, and that the from is its dest
            let hosted_alias = hosted_aliases
                .get(&alias_key.get_location())
                .ok_or(ErrorKind::NoSuchAlias)?;

            let span = hosted_alias.span(Some(span));
            let _enter = span.enter();

            if *hosted_alias.dest_key() != from {
                // We have received a request from a node that is not the dest of the alias.
                return Err(ErrorKind::AliasOwner.into());
            }

            // query the predecessor, and then reply
            if let Some((pred, _addr)) =
                requests.fetch_predecessor_of(connections, of.clone()).await
            {
                // return the pred
                let data = AliasResponse::Pred {
                    pred: pred.clone(),
                    of,
                }
                .serialize_encrypt(hosted_alias.alias_key())?;
                let msg = MemberMessage::AliasResponse {
                    to: from.get_location(),
                    from: hosted_alias.alias_key().get_location(),
                    data: data.to_vec(),
                };
                // connections.route_msg(from.get_location(), &msg).await;
                trace!(
                    "Sending Pred (immediate) to dest {:?}",
                    hosted_alias.dest_key()
                );
                if from == connections.self_id().get_public_key() {
                    connections.send_self(msg);
                } else {
                    connections.route_msg(from.get_location(), &msg).await;
                }
            } else {
                // store that we have requested a pred for this alias
                trace!("Pred requires query, pending...");
                let list = alias_pred_requests.entry(of).or_default();
                list.push(hosted_alias.alias_key().get_location());
            }
        }

        AliasOperation::Ping(alias_key) => {
            // Check that we actually host the alias, and that the from is its dest
            let hosted_alias = hosted_aliases
                .get(&alias_key.get_location())
                .ok_or(ErrorKind::NoSuchAlias)?;
            let span = hosted_alias.span(Some(span));
            let _enter = span.enter();
            if *hosted_alias.dest_key() != from {
                // We have received a request from a node that is not the dest of the alias.
                return Err(ErrorKind::AliasOwner.into());
            }
            trace!("Received Ping, replying to {:?}", to);

            let data = AliasResponse::Alive.serialize_encrypt(hosted_alias.alias_key())?;
            let msg = MemberMessage::AliasResponse {
                to: hosted_alias.dest_key().get_location(),
                from: hosted_alias.alias_key().get_location(),
                data: data.to_vec(),
            };
            // connections.route_msg(to, msg).await;
            if to == connections.self_id().get_location() {
                connections.send_self(msg);
            } else {
                connections.route_msg(to, &msg).await;
            }
        }

        // This node has been requested to send a request to its extension
        AliasOperation::Forward {
            alias_key,
            to_host,
            to_alias,
            data,
        } => {
            // This is where AliasOperations are re-signed. The dest node only
            // knows of the forwarder, so it will check the sig against that
            // key. However, the unwrapped message will already be encrypted for
            // the dest. Therefore, sign the already encrypted message with our
            // key.
            if let Some(hosted_alias) = hosted_aliases.get(&alias_key.get_location()) {
                let span = hosted_alias.span(Some(span));
                let _enter = span.enter();
                trace!("Forwarding AliasOperation to {:?}", to_host);
                match forwarded_addrs.get(&to_host) {
                    Some(forwarding_addr) => {
                        // If the forwarding addr is already taken, then skip forwarding
                        if *forwarding_addr != hosted_alias.alias_key().get_location() {
                            info!("Forwarding address collision");
                            return Ok(());
                        }
                    }
                    None => {
                        // If there is no forwarding address, add it
                        trace!(
                            "Inserting forwarded addrs {:?} => {:?}",
                            to_alias,
                            hosted_alias.alias_key()
                        );
                        forwarded_addrs
                            .insert(to_alias.clone(), hosted_alias.alias_key().get_location());
                    }
                }

                let sig = connections.self_id().sign(&data).to_vec();
                let from = connections.self_id().get_public_key();
                let msg = MemberMessage::AliasOperation {
                    to: to_host.clone(),
                    from,
                    op: data,
                    sig,
                };

                if to_host == connections.self_id().get_location() {
                    connections.send_self(msg);
                } else {
                    connections.route_msg(to_host, &msg).await;
                }
            } else {
                trace!("AliasOperation not forwarded, no such alias");
            }
        }
    }

    Ok(())
}
