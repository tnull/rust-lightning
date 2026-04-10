// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains the swap-in-potentiam service handler, [`SIPServiceHandler`].

use alloc::string::ToString;

use super::event::SIPServiceEvent;
use super::msgs::{
	SIPGetInfoResponse, SIPMessage, SIPRegisterUtxoRequest, SIPRequest, SIPResponse, SIPSwapRequest,
};
use crate::events::EventQueue;
use crate::lsps0::ser::{LSPSProtocolMessageHandler, LSPSRequestId};
use crate::message_queue::MessageQueue;
use crate::sync::Arc;

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::util::logger::Level;
use lightning::util::persist::KVStore;

use bitcoin::secp256k1::PublicKey;

/// Service-side configuration for swap-in-potentiam.
#[derive(Clone, Debug)]
pub struct SIPServiceConfig {
	/// The server's public key for SIP address construction.
	pub server_pubkey: PublicKey,
	/// The CSV delay (in blocks) for the refund path.
	pub csv_delay: u16,
	/// Minimum swap amount in satoshis.
	pub min_swap_amount_sat: u64,
	/// Maximum swap amount in satoshis.
	pub max_swap_amount_sat: u64,
	/// Minimum number of confirmations required before accepting a swap.
	pub min_confirmations: u16,
}

/// The service-side handler for the swap-in-potentiam protocol.
///
/// This handler manages the protocol flow for an LSP that accepts SIP deposits from clients
/// and facilitates swaps into Lightning channels.
pub struct SIPServiceHandler<K: KVStore + Clone> {
	pending_messages: Arc<MessageQueue>,
	pending_events: Arc<EventQueue<K>>,
	config: SIPServiceConfig,
}

impl<K: KVStore + Clone> SIPServiceHandler<K> {
	/// Constructs a `SIPServiceHandler`.
	pub(crate) fn new(
		pending_messages: Arc<MessageQueue>, pending_events: Arc<EventQueue<K>>,
		config: SIPServiceConfig,
	) -> Self {
		Self { pending_messages, pending_events, config }
	}

	/// Returns a reference to the service configuration.
	pub fn config(&self) -> &SIPServiceConfig {
		&self.config
	}

	fn handle_get_info(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		let mut message_queue_notifier = self.pending_messages.notifier();

		let response = SIPGetInfoResponse {
			server_pubkey: self.config.server_pubkey,
			csv_delay: self.config.csv_delay,
			min_swap_amount_sat: self.config.min_swap_amount_sat,
			max_swap_amount_sat: self.config.max_swap_amount_sat,
			min_confirmations: self.config.min_confirmations,
		};

		let msg = SIPMessage::Response(request_id, SIPResponse::GetInfo(response)).into();
		message_queue_notifier.enqueue(counterparty_node_id, msg);
		Ok(())
	}

	fn handle_register_utxo(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey,
		params: SIPRegisterUtxoRequest,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		// Emit an event so that the application can validate the UTXO and respond.
		event_queue_notifier.enqueue(SIPServiceEvent::UtxoRegistered {
			counterparty_node_id: *counterparty_node_id,
			request_id,
			outpoint: params.outpoint,
			value_sat: params.value_sat,
			user_pubkey: params.user_pubkey,
		});

		Ok(())
	}

	fn handle_swap_request(
		&self, request_id: LSPSRequestId, counterparty_node_id: &PublicKey, params: SIPSwapRequest,
	) -> Result<(), LightningError> {
		let event_queue_notifier = self.pending_events.notifier();

		// Emit an event so that the application can validate and initiate the swap.
		event_queue_notifier.enqueue(SIPServiceEvent::SwapRequested {
			counterparty_node_id: *counterparty_node_id,
			request_id,
			utxos: params.utxos,
			channel_id: params.channel_id,
		});

		Ok(())
	}
}

impl<K: KVStore + Clone> LSPSProtocolMessageHandler for SIPServiceHandler<K> {
	type ProtocolMessage = SIPMessage;
	const PROTOCOL_NUMBER: Option<u16> = None;

	fn handle_message(
		&self, message: Self::ProtocolMessage, counterparty_node_id: &PublicKey,
	) -> Result<(), LightningError> {
		match message {
			SIPMessage::Request(request_id, request) => match request {
				SIPRequest::GetInfo(_) => self.handle_get_info(request_id, counterparty_node_id),
				SIPRequest::RegisterUtxo(params) => {
					self.handle_register_utxo(request_id, counterparty_node_id, params)
				},
				SIPRequest::SwapRequest(params) => {
					self.handle_swap_request(request_id, counterparty_node_id, params)
				},
			},
			_ => Err(LightningError {
				err: "SIP service handler received a response, expected a request".to_string(),
				action: ErrorAction::IgnoreAndLog(Level::Debug),
			}),
		}
	}
}
