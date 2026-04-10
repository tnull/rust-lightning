// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Events emitted by the swap-in-potentiam protocol handlers.

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint};

/// Events emitted by the SIP client handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SIPClientEvent {
	/// The LSP responded with its SIP parameters.
	///
	/// The client should use these parameters to construct SIP addresses and configure the SIP
	/// wallet.
	GetInfoResponse {
		/// The LSP's node id.
		lsp_node_id: PublicKey,
		/// The server's public key for SIP address construction.
		server_pubkey: PublicKey,
		/// The CSV delay (in blocks) for the refund path.
		csv_delay: u16,
		/// Minimum swap amount in satoshis.
		min_swap_amount_sat: u64,
		/// Maximum swap amount in satoshis.
		max_swap_amount_sat: u64,
		/// Minimum confirmations required.
		min_confirmations: u16,
	},
	/// The LSP's response to getting info failed.
	GetInfoFailed {
		/// The LSP's node id.
		lsp_node_id: PublicKey,
		/// The error message.
		error: String,
	},
	/// The LSP accepted a UTXO registration.
	UtxoRegistered {
		/// The LSP's node id.
		lsp_node_id: PublicKey,
		/// The outpoint that was registered.
		outpoint: OutPoint,
	},
	/// The LSP rejected a UTXO registration.
	UtxoRegistrationFailed {
		/// The LSP's node id.
		lsp_node_id: PublicKey,
		/// The outpoint that was rejected.
		outpoint: OutPoint,
		/// The reason for rejection.
		reason: String,
	},
	/// The LSP accepted a swap request.
	SwapAccepted {
		/// The LSP's node id.
		lsp_node_id: PublicKey,
		/// The outpoints being swapped.
		utxos: Vec<OutPoint>,
		/// The channel ID for the swap.
		channel_id: String,
	},
	/// The LSP rejected a swap request.
	SwapFailed {
		/// The LSP's node id.
		lsp_node_id: PublicKey,
		/// The reason for rejection.
		reason: String,
	},
}

/// Events emitted by the SIP service handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SIPServiceEvent {
	/// A client registered a new SIP UTXO.
	///
	/// The service should validate that the outpoint's scriptPubKey matches the expected SIP
	/// address and respond accordingly.
	UtxoRegistered {
		/// The client's node id.
		counterparty_node_id: PublicKey,
		/// The request id (needed for responding).
		request_id: crate::lsps0::ser::LSPSRequestId,
		/// The outpoint the client claims to have deposited to.
		outpoint: OutPoint,
		/// The value claimed by the client in satoshis.
		value_sat: u64,
		/// The user's public key for this SIP address.
		user_pubkey: PublicKey,
	},
	/// A client requested swapping SIP UTXOs into a channel.
	///
	/// The service should validate the UTXOs, initiate the channel open or splice, and respond.
	SwapRequested {
		/// The client's node id.
		counterparty_node_id: PublicKey,
		/// The request id (needed for responding).
		request_id: crate::lsps0::ser::LSPSRequestId,
		/// The outpoints the client wants to swap.
		utxos: Vec<OutPoint>,
		/// The target channel ID, if splicing into an existing channel.
		channel_id: Option<String>,
	},
}

/// SIP-specific events that the service considers important enough to persist.
///
/// These events require idempotent handling since they may be replayed after a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SIPServicePersistedEvent {
	/// A swap has been accepted and the service should initiate a channel open or splice.
	///
	/// This is persisted so the channel operation can be retried after a restart.
	OpenChannel {
		/// The client's node id.
		counterparty_node_id: PublicKey,
		/// The outpoints being swapped.
		utxos: Vec<OutPoint>,
		/// The total value being swapped in satoshis.
		total_value: Amount,
		/// The channel ID, if splicing into an existing channel.
		channel_id: Option<String>,
	},
}
