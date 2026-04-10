// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the swap-in-potentiam client handler, [`SIPClientHandler`].

use alloc::string::ToString;

use super::event::SIPClientEvent;
use super::msgs::{
	SIPGetInfoRequest, SIPGetInfoResponse, SIPMessage, SIPRegisterUtxoRequest,
	SIPRegisterUtxoResponse, SIPRequest, SIPResponse, SIPSwapRequest, SIPSwapResponse,
};
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId, LSPSResponseError};
use crate::message_queue::MessageQueue;
use crate::prelude::{new_hash_map, HashMap, HashSet};
use crate::sync::{Arc, Mutex, RwLock};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::sign::EntropySource;
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;

use bitcoin::secp256k1::PublicKey;
use bitcoin::OutPoint;

/// Client-side configuration for swap-in-potentiam.
#[derive(Clone, Debug)]
pub struct SIPClientConfig {}

#[derive(Default)]
struct PeerState {
	pending_get_info_requests: HashSet<LSPSRequestId>,
	pending_register_utxo_requests: HashMap<LSPSRequestId, OutPoint>,
	pending_swap_requests: HashSet<LSPSRequestId>,
}

/// The client-side handler for the swap-in-potentiam protocol.
///
/// This handler manages the protocol flow for a wallet user that wants to swap on-chain funds
/// deposited at SIP addresses into Lightning channels via their LSP.
pub struct SIPClientHandler<ES: EntropySource, K: KVStore + Clone> {
	entropy_source: ES,
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<PeerState>>>,
	#[allow(dead_code)]
	config: SIPClientConfig,
}

impl<ES: EntropySource, K: KVStore + Clone> SIPClientHandler<ES, K> {
	/// Constructs a `SIPClientHandler`.
	pub(crate) fn new(
		entropy_source: ES, pending_messages: Arc<MessageQueue>,
		pending_events: Arc<EventQueue<K>>, config: SIPClientConfig,
	) -> Self {
		Self {
			entropy_source,
			pending_messages,
			pending_events,
			per_peer_state: RwLock::new(new_hash_map()),
			config,
		}
	}

	/// Request the LSP's swap-in-potentiam parameters.
	///
	/// The response will be emitted as a [`SIPClientEvent::GetInfoResponse`].
	pub fn request_sip_info(&self, counterparty_node_id: PublicKey) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_get_info_requests.insert(request_id.clone());
		}

		let request = SIPRequest::GetInfo(SIPGetInfoRequest {});
		let msg = SIPMessage::Request(request_id.clone(), request).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);
		request_id
	}

	/// Notify the LSP about a deposit to a SIP address.
	///
	/// The response will be emitted as a [`SIPClientEvent::UtxoRegistered`] or
	/// [`SIPClientEvent::UtxoRegistrationFailed`].
	pub fn register_utxo(
		&self, counterparty_node_id: PublicKey, outpoint: OutPoint, value_sat: u64,
		user_pubkey: PublicKey,
	) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_register_utxo_requests.insert(request_id.clone(), outpoint);
		}

		let request =
			SIPRequest::RegisterUtxo(SIPRegisterUtxoRequest { outpoint, value_sat, user_pubkey });
		let msg = SIPMessage::Request(request_id.clone(), request).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);
		request_id
	}

	/// Request swapping confirmed SIP UTXOs into a Lightning channel.
	///
	/// The response will be emitted as a [`SIPClientEvent::SwapAccepted`] or
	/// [`SIPClientEvent::SwapFailed`].
	pub fn request_swap(
		&self, counterparty_node_id: PublicKey, utxos: alloc::vec::Vec<OutPoint>,
		channel_id: Option<alloc::string::String>,
	) -> LSPSRequestId {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let request_id = crate::utils::generate_request_id(&self.entropy_source);
		{
			let mut outer_state_lock = self.per_peer_state.write().unwrap();
			let inner_state_lock = outer_state_lock
				.entry(counterparty_node_id)
				.or_insert(Mutex::new(PeerState::default()));
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			peer_state_lock.pending_swap_requests.insert(request_id.clone());
		}

		let request = SIPRequest::SwapRequest(SIPSwapRequest { utxos, channel_id });
		let msg = SIPMessage::Request(request_id.clone(), request).into();
		message_queue_notifier.enqueue(&counterparty_node_id, msg);
		request_id
	}

	fn handle_get_info_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		result: SIPGetInfoResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		match outer_state_lock.get(counterparty_node_id) {
			Some(inner_state_lock) => {
				let mut peer_state_lock = inner_state_lock.lock().unwrap();
				if !peer_state_lock.pending_get_info_requests.remove(&request_id) {
					return Err(LightningError {
						err: format!(
							"Received SIP get_info response for unknown request: {:?}",
							request_id
						),
						action: ErrorAction::IgnoreAndLog(Level::Debug),
					});
				}

				event_queue_notifier.enqueue(SIPClientEvent::GetInfoResponse {
					lsp_node_id: *counterparty_node_id,
					server_pubkey: result.server_pubkey,
					csv_delay: result.csv_delay,
					min_swap_amount_sat: result.min_swap_amount_sat,
					max_swap_amount_sat: result.max_swap_amount_sat,
					min_confirmations: result.min_confirmations,
				});
			},
			None => {
				return Err(LightningError {
					err: format!(
						"Received SIP get_info response from unknown peer: {}",
						counterparty_node_id
					),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}

		Ok(())
	}

	fn handle_get_info_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			if peer_state_lock.pending_get_info_requests.remove(&request_id) {
				event_queue_notifier.enqueue(SIPClientEvent::GetInfoFailed {
					lsp_node_id: *counterparty_node_id,
					error: error.message,
				});
			}
		}

		Ok(())
	}

	fn handle_register_utxo_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		result: SIPRegisterUtxoResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			if let Some(outpoint) =
				peer_state_lock.pending_register_utxo_requests.remove(&request_id)
			{
				if result.accepted {
					event_queue_notifier.enqueue(SIPClientEvent::UtxoRegistered {
						lsp_node_id: *counterparty_node_id,
						outpoint,
					});
				} else {
					event_queue_notifier.enqueue(SIPClientEvent::UtxoRegistrationFailed {
						lsp_node_id: *counterparty_node_id,
						outpoint,
						reason: result.reason.unwrap_or_else(|| "Unknown reason".to_string()),
					});
				}
			}
		}

		Ok(())
	}

	fn handle_register_utxo_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			if let Some(outpoint) =
				peer_state_lock.pending_register_utxo_requests.remove(&request_id)
			{
				event_queue_notifier.enqueue(SIPClientEvent::UtxoRegistrationFailed {
					lsp_node_id: *counterparty_node_id,
					outpoint,
					reason: error.message,
				});
			}
		}

		Ok(())
	}

	fn handle_swap_response(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey, result: SIPSwapResponse,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			if peer_state_lock.pending_swap_requests.remove(&request_id) {
				if result.accepted {
					if let Some(channel_id) = result.channel_id {
						event_queue_notifier.enqueue(SIPClientEvent::SwapAccepted {
							lsp_node_id: *counterparty_node_id,
							utxos: alloc::vec::Vec::new(), // TODO: track UTXOs per request
							channel_id,
						});
					}
				} else {
					event_queue_notifier.enqueue(SIPClientEvent::SwapFailed {
						lsp_node_id: *counterparty_node_id,
						reason: result.reason.unwrap_or_else(|| "Unknown reason".to_string()),
					});
				}
			}
		}

		Ok(())
	}

	fn handle_swap_error(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		error: LSPSResponseError,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		let outer_state_lock = self.per_peer_state.read().unwrap();
		if let Some(inner_state_lock) = outer_state_lock.get(counterparty_node_id) {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			if peer_state_lock.pending_swap_requests.remove(&request_id) {
				event_queue_notifier.enqueue(SIPClientEvent::SwapFailed {
					lsp_node_id: *counterparty_node_id,
					reason: error.message,
				});
			}
		}

		Ok(())
	}
}

impl<ES: EntropySource, K: KVStore + Clone> LSPSProtocolMessageHandler for SIPClientHandler<ES, K> {
	type ProtocolMessage = SIPMessage;
	const PROTOCOL_NUMBER: Option<u16> = None;

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			SIPMessage::Response(request_id, response) => match response {
				SIPResponse::GetInfo(result) => {
					self.handle_get_info_response(request_id, counterparty_node_id, result)
				},
				SIPResponse::GetInfoError(error) => {
					self.handle_get_info_error(request_id, counterparty_node_id, error)
				},
				SIPResponse::RegisterUtxo(result) => {
					self.handle_register_utxo_response(request_id, counterparty_node_id, result)
				},
				SIPResponse::RegisterUtxoError(error) => {
					self.handle_register_utxo_error(request_id, counterparty_node_id, error)
				},
				SIPResponse::SwapRequest(result) => {
					self.handle_swap_response(request_id, counterparty_node_id, result)
				},
				SIPResponse::SwapRequestError(error) => {
					self.handle_swap_error(request_id, counterparty_node_id, error)
				},
			},
			_ => {
				return Err(LightningError {
					err: "SIP client handler received a request, expected a response".to_string(),
					action: ErrorAction::IgnoreAndLog(Level::Debug),
				});
			},
		}
	}
}
