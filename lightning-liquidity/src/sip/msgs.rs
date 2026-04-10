// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Message types for the swap-in-potentiam protocol.
//!
//! These messages are transported via the LSPS0 JSON-RPC layer.

use alloc::string::String;
use alloc::vec::Vec;

use core::convert::TryFrom;

use crate::lsps0::ser::{LSPSMessage, LSPSRequestId, LSPSResponseError};

use bitcoin::secp256k1::PublicKey;
use bitcoin::OutPoint;

use serde::{Deserialize, Serialize};

pub(crate) const SIP_GET_INFO_METHOD_NAME: &str = "sip.get_info";
pub(crate) const SIP_REGISTER_UTXO_METHOD_NAME: &str = "sip.register_utxo";
pub(crate) const SIP_SWAP_REQUEST_METHOD_NAME: &str = "sip.swap_request";

/// A request to retrieve the LSP's swap-in-potentiam parameters.
///
/// The client sends this to learn the server's public key for SIP address construction,
/// the supported CSV delay, fee schedule, and swap amount limits.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct SIPGetInfoRequest {}

/// The LSP's swap-in-potentiam parameters.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SIPGetInfoResponse {
	/// The server's public key to use when constructing SIP addresses.
	pub server_pubkey: PublicKey,
	/// The relative timelock (in blocks) for the refund spending path.
	pub csv_delay: u16,
	/// The minimum swap amount in satoshis.
	pub min_swap_amount_sat: u64,
	/// The maximum swap amount in satoshis.
	pub max_swap_amount_sat: u64,
	/// The minimum number of confirmations required before a swap is accepted.
	pub min_confirmations: u16,
}

/// A request to notify the LSP about a deposit to a SIP address.
///
/// The client sends this after detecting an on-chain deposit to a SIP address. The LSP
/// validates that the outpoint's scriptPubKey matches the expected SIP address derived from
/// the provided public key and its own key.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SIPRegisterUtxoRequest {
	/// The outpoint of the deposit.
	pub outpoint: OutPoint,
	/// The value of the deposit in satoshis.
	pub value_sat: u64,
	/// The user's public key used in this SIP address.
	pub user_pubkey: PublicKey,
}

/// Response to a UTXO registration request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SIPRegisterUtxoResponse {
	/// Whether the LSP has accepted and is now tracking this UTXO.
	pub accepted: bool,
	/// An optional reason if the UTXO was not accepted.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
}

/// A request to swap confirmed SIP UTXOs into a Lightning channel.
///
/// The client can request either a new channel open or a splice-in to an existing channel.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SIPSwapRequest {
	/// The outpoints of the SIP UTXOs to swap.
	pub utxos: Vec<OutPoint>,
	/// If set, splice into this existing channel. If `None`, open a new channel.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub channel_id: Option<String>,
}

/// Response to a swap request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct SIPSwapResponse {
	/// Whether the swap was accepted.
	pub accepted: bool,
	/// The channel ID for the swap (new or existing).
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub channel_id: Option<String>,
	/// An optional reason if the swap was not accepted.
	#[serde(default)]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reason: Option<String>,
}

/// An enum capturing all valid JSON-RPC requests in the SIP protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SIPRequest {
	/// A request to retrieve the LSP's SIP parameters.
	GetInfo(SIPGetInfoRequest),
	/// A request to register a UTXO deposit.
	RegisterUtxo(SIPRegisterUtxoRequest),
	/// A request to swap SIP UTXOs into a channel.
	SwapRequest(SIPSwapRequest),
}

/// An enum capturing all valid JSON-RPC responses in the SIP protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SIPResponse {
	/// A successful response to a [`SIPGetInfoRequest`].
	GetInfo(SIPGetInfoResponse),
	/// An error response to a [`SIPGetInfoRequest`].
	GetInfoError(LSPSResponseError),
	/// A successful response to a [`SIPRegisterUtxoRequest`].
	RegisterUtxo(SIPRegisterUtxoResponse),
	/// An error response to a [`SIPRegisterUtxoRequest`].
	RegisterUtxoError(LSPSResponseError),
	/// A successful response to a [`SIPSwapRequest`].
	SwapRequest(SIPSwapResponse),
	/// An error response to a [`SIPSwapRequest`].
	SwapRequestError(LSPSResponseError),
}

/// An enum capturing all valid JSON-RPC messages in the SIP protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SIPMessage {
	/// A SIP JSON-RPC request.
	Request(LSPSRequestId, SIPRequest),
	/// A SIP JSON-RPC response.
	Response(LSPSRequestId, SIPResponse),
}

impl TryFrom<LSPSMessage> for SIPMessage {
	type Error = ();

	fn try_from(message: LSPSMessage) -> Result<Self, Self::Error> {
		if let LSPSMessage::SIP(message) = message {
			return Ok(message);
		}

		Err(())
	}
}

impl From<SIPMessage> for LSPSMessage {
	fn from(message: SIPMessage) -> Self {
		LSPSMessage::SIP(message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hashes::Hash;

	#[test]
	fn test_get_info_request_serialization() {
		let req = SIPGetInfoRequest {};
		let json = serde_json::to_string(&req).unwrap();
		let deserialized: SIPGetInfoRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(req, deserialized);
	}

	#[test]
	fn test_get_info_response_serialization() {
		let secp = bitcoin::secp256k1::Secp256k1::new();
		let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap();
		let pk = PublicKey::from_secret_key(&secp, &sk);

		let resp = SIPGetInfoResponse {
			server_pubkey: pk,
			csv_delay: 2016,
			min_swap_amount_sat: 10_000,
			max_swap_amount_sat: 10_000_000,
			min_confirmations: 3,
		};
		let json = serde_json::to_string(&resp).unwrap();
		let deserialized: SIPGetInfoResponse = serde_json::from_str(&json).unwrap();
		assert_eq!(resp, deserialized);
	}

	#[test]
	fn test_register_utxo_request_serialization() {
		let secp = bitcoin::secp256k1::Secp256k1::new();
		let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap();
		let pk = PublicKey::from_secret_key(&secp, &sk);

		let txid_bytes = [0xab; 32];
		let txid = bitcoin::Txid::from_byte_array(txid_bytes);

		let req = SIPRegisterUtxoRequest {
			outpoint: OutPoint::new(txid, 0),
			value_sat: 50_000,
			user_pubkey: pk,
		};
		let json = serde_json::to_string(&req).unwrap();
		let deserialized: SIPRegisterUtxoRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(req, deserialized);
	}

	#[test]
	fn test_swap_request_serialization() {
		let txid_bytes = [0xcd; 32];
		let txid = bitcoin::Txid::from_byte_array(txid_bytes);

		let req = SIPSwapRequest {
			utxos: vec![OutPoint::new(txid, 0), OutPoint::new(txid, 1)],
			channel_id: Some("abc123".to_string()),
		};
		let json = serde_json::to_string(&req).unwrap();
		let deserialized: SIPSwapRequest = serde_json::from_str(&json).unwrap();
		assert_eq!(req, deserialized);
	}
}
