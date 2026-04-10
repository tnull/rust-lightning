// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Swap-in-potentiam address construction and witness building.
//!
//! A SIP address is a P2WSH address encoding a script with two spending paths:
//!
//! - **Cooperative path:** A 2-of-2 multisig requiring signatures from both the user and the
//!   server (LSP). Used for swapping funds into a Lightning channel.
//!
//! - **Refund path:** After a relative timelock (CSV) expires, the user can spend unilaterally
//!   without the server's cooperation. This is the recovery mechanism if the server becomes
//!   unavailable.

use bitcoin::blockdata::opcodes::all as opcodes;
use bitcoin::blockdata::script::{Builder, ScriptBuf};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, Weight, Witness};

/// Converts a `secp256k1::PublicKey` to a `bitcoin::PublicKey` for use in script construction.
fn to_bitcoin_pubkey(key: &PublicKey) -> bitcoin::PublicKey {
	bitcoin::PublicKey { inner: *key, compressed: true }
}

/// The witness script for a swap-in-potentiam address.
///
/// The script has two branches:
///
/// ```text
/// OP_IF
///   OP_2 <user_key> <server_key> OP_2 OP_CHECKMULTISIG
/// OP_ELSE
///   <csv_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
///   <user_key> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// The cooperative branch (OP_IF) requires signatures from both parties. The refund branch
/// (OP_ELSE) requires only the user's signature after the CSV delay has elapsed.
pub fn build_sip_witness_script(
	user_key: &PublicKey, server_key: &PublicKey, csv_delay: u16,
) -> ScriptBuf {
	let user_btc_key = to_bitcoin_pubkey(user_key);
	let server_btc_key = to_bitcoin_pubkey(server_key);

	Builder::new()
		.push_opcode(opcodes::OP_IF)
		.push_opcode(opcodes::OP_PUSHNUM_2)
		.push_key(&user_btc_key)
		.push_key(&server_btc_key)
		.push_opcode(opcodes::OP_PUSHNUM_2)
		.push_opcode(opcodes::OP_CHECKMULTISIG)
		.push_opcode(opcodes::OP_ELSE)
		.push_int(csv_delay as i64)
		.push_opcode(opcodes::OP_CSV)
		.push_opcode(opcodes::OP_DROP)
		.push_key(&user_btc_key)
		.push_opcode(opcodes::OP_CHECKSIG)
		.push_opcode(opcodes::OP_ENDIF)
		.into_script()
}

/// Derives the P2WSH address for a swap-in-potentiam witness script.
pub fn sip_p2wsh_address(witness_script: &ScriptBuf, network: Network) -> Address {
	Address::p2wsh(witness_script, network)
}

/// Builds the witness for spending via the cooperative (2-of-2 multisig) path.
///
/// The witness stack is: `<> <user_sig> <server_sig> <TRUE> <witness_script>`
///
/// The empty first element is the OP_CHECKMULTISIG dummy required by the Bitcoin consensus rules.
/// `TRUE` selects the OP_IF (cooperative) branch.
pub fn build_cooperative_witness(
	user_sig: &bitcoin::ecdsa::Signature, server_sig: &bitcoin::ecdsa::Signature,
	witness_script: &ScriptBuf,
) -> Witness {
	let mut witness = Witness::new();
	// OP_CHECKMULTISIG dummy element (off-by-one bug in Bitcoin consensus).
	witness.push([]);
	witness.push(user_sig.serialize());
	witness.push(server_sig.serialize());
	// OP_TRUE to enter the OP_IF branch.
	witness.push([0x01]);
	witness.push(witness_script.as_bytes());
	witness
}

/// Builds the witness for spending via the refund (CSV timeout) path.
///
/// The witness stack is: `<user_sig> <FALSE> <witness_script>`
///
/// `FALSE` selects the OP_ELSE (refund) branch. The spending transaction's input must have its
/// sequence set to at least the CSV delay value.
pub fn build_refund_witness(
	user_sig: &bitcoin::ecdsa::Signature, witness_script: &ScriptBuf,
) -> Witness {
	let mut witness = Witness::new();
	witness.push(user_sig.serialize());
	// OP_FALSE to enter the OP_ELSE branch.
	witness.push([]);
	witness.push(witness_script.as_bytes());
	witness
}

/// Returns the satisfaction weight for the cooperative spending path.
///
/// This is the weight of the witness data only (not the input's other fields). Used for fee
/// estimation when including SIP UTXOs in a funding or splice transaction.
///
/// Witness items for cooperative spend:
/// - 1 byte: witness item count (5 items)
/// - 1 byte: empty dummy element length (0)
/// - 1 byte + 72 bytes: user signature (length prefix + DER signature + sighash byte)
/// - 1 byte + 72 bytes: server signature (length prefix + DER signature + sighash byte)
/// - 1 byte + 1 byte: OP_TRUE branch selector (length prefix + 0x01)
/// - varint + script: witness script push
///
/// We use worst-case 72-byte DER signatures for conservative fee estimation.
pub fn cooperative_spend_satisfaction_weight(witness_script: &ScriptBuf) -> Weight {
	let script_len = witness_script.len();
	let script_push_len = if script_len < 253 { 1 } else { 3 };

	let witness_bytes: u64 = 1 // witness item count (compact size for 5 items)
		+ 1                    // empty dummy: length prefix (0x00)
		+ 1 + 72              // user sig: length prefix + worst-case DER
		+ 1 + 72              // server sig: length prefix + worst-case DER
		+ 1 + 1               // branch selector: length prefix + 0x01
		+ script_push_len     // witness script: length prefix
		+ script_len as u64; // witness script: data

	Weight::from_witness_data_size(witness_bytes)
}

/// Returns the satisfaction weight for the refund spending path.
///
/// Witness items for refund spend:
/// - 1 byte: witness item count (3 items)
/// - 1 byte + 72 bytes: user signature (length prefix + DER signature + sighash byte)
/// - 1 byte: empty branch selector (OP_FALSE, length prefix 0x00)
/// - varint + script: witness script push
pub fn refund_spend_satisfaction_weight(witness_script: &ScriptBuf) -> Weight {
	let script_len = witness_script.len();
	let script_push_len = if script_len < 253 { 1 } else { 3 };

	let witness_bytes: u64 = 1 // witness item count (compact size for 3 items)
		+ 1 + 72              // user sig: length prefix + worst-case DER
		+ 1                   // branch selector: length prefix (0x00 for empty/FALSE)
		+ script_push_len     // witness script: length prefix
		+ script_len as u64; // witness script: data

	Weight::from_witness_data_size(witness_bytes)
}

#[cfg(test)]
mod tests {
	use super::*;

	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use bitcoin::sighash::SighashCache;
	use bitcoin::{
		transaction, Amount, EcdsaSighashType, OutPoint, Sequence, Transaction, TxIn, TxOut,
	};

	fn test_keys() -> (SecretKey, PublicKey, SecretKey, PublicKey) {
		let secp = Secp256k1::new();
		let user_sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
		let user_pk = PublicKey::from_secret_key(&secp, &user_sk);
		let server_sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
		let server_pk = PublicKey::from_secret_key(&secp, &server_sk);
		(user_sk, user_pk, server_sk, server_pk)
	}

	fn create_funding_tx(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
		Transaction {
			version: transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::null(),
				script_sig: ScriptBuf::new(),
				sequence: Sequence::MAX,
				witness: Witness::new(),
			}],
			output: vec![TxOut { value, script_pubkey }],
		}
	}

	fn create_spending_tx(
		funding_tx: &Transaction, funding_vout: u32, sequence: Sequence,
	) -> Transaction {
		Transaction {
			version: transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint::new(funding_tx.compute_txid(), funding_vout),
				script_sig: ScriptBuf::new(),
				sequence,
				witness: Witness::new(),
			}],
			output: vec![TxOut {
				value: Amount::from_sat(49_000),
				script_pubkey: ScriptBuf::new_p2wpkh(
					&bitcoin::WPubkeyHash::from_slice(&[0; 20]).unwrap(),
				),
			}],
		}
	}

	#[test]
	fn test_build_sip_witness_script() {
		let (_user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let csv_delay = 2016u16;
		let script = build_sip_witness_script(&user_pk, &server_pk, csv_delay);

		// Script should be non-empty and parseable.
		assert!(!script.is_empty());

		// Verify script contains expected opcodes by checking the raw bytes include our keys.
		let script_bytes = script.as_bytes();
		assert!(
			script_bytes.windows(33).any(|w| w == user_pk.serialize()),
			"Script should contain user pubkey"
		);
		assert!(
			script_bytes.windows(33).any(|w| w == server_pk.serialize()),
			"Script should contain server pubkey"
		);
	}

	#[test]
	fn test_sip_p2wsh_address() {
		let (_user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let script = build_sip_witness_script(&user_pk, &server_pk, 2016);
		let address = sip_p2wsh_address(&script, Network::Regtest);

		// Should be a valid bech32 address.
		assert!(address.to_string().starts_with("bcrt1"));
	}

	#[test]
	fn test_deterministic_address() {
		let (_user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let script1 = build_sip_witness_script(&user_pk, &server_pk, 2016);
		let script2 = build_sip_witness_script(&user_pk, &server_pk, 2016);
		assert_eq!(script1, script2, "Same inputs should produce the same script");

		let addr1 = sip_p2wsh_address(&script1, Network::Regtest);
		let addr2 = sip_p2wsh_address(&script2, Network::Regtest);
		assert_eq!(addr1, addr2, "Same script should produce the same address");
	}

	#[test]
	fn test_different_csv_produces_different_address() {
		let (_user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let script_a = build_sip_witness_script(&user_pk, &server_pk, 2016);
		let script_b = build_sip_witness_script(&user_pk, &server_pk, 4032);
		assert_ne!(script_a, script_b);
	}

	#[test]
	fn test_cooperative_spend_valid() {
		let secp = Secp256k1::new();
		let (user_sk, user_pk, server_sk, server_pk) = test_keys();
		let csv_delay = 2016u16;
		let witness_script = build_sip_witness_script(&user_pk, &server_pk, csv_delay);
		let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
		let value = Amount::from_sat(50_000);

		let funding_tx = create_funding_tx(script_pubkey, value);
		let mut spending_tx = create_spending_tx(&funding_tx, 0, Sequence::ENABLE_RBF_NO_LOCKTIME);

		// Sign the cooperative spend.
		let sighash = SighashCache::new(&spending_tx)
			.p2wsh_signature_hash(0, &witness_script, value, EcdsaSighashType::All)
			.unwrap();

		let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
		let user_sig = bitcoin::ecdsa::Signature {
			signature: secp.sign_ecdsa(&msg, &user_sk),
			sighash_type: EcdsaSighashType::All,
		};
		let server_sig = bitcoin::ecdsa::Signature {
			signature: secp.sign_ecdsa(&msg, &server_sk),
			sighash_type: EcdsaSighashType::All,
		};

		spending_tx.input[0].witness =
			build_cooperative_witness(&user_sig, &server_sig, &witness_script);

		// Verify the witness is correctly structured (5 items).
		assert_eq!(spending_tx.input[0].witness.len(), 5);
	}

	#[test]
	fn test_refund_spend_valid() {
		let secp = Secp256k1::new();
		let (user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let csv_delay = 2016u16;
		let witness_script = build_sip_witness_script(&user_pk, &server_pk, csv_delay);
		let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
		let value = Amount::from_sat(50_000);

		let funding_tx = create_funding_tx(script_pubkey, value);
		let mut spending_tx =
			create_spending_tx(&funding_tx, 0, Sequence::from_consensus(csv_delay as u32));

		// Sign the refund spend.
		let sighash = SighashCache::new(&spending_tx)
			.p2wsh_signature_hash(0, &witness_script, value, EcdsaSighashType::All)
			.unwrap();

		let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
		let user_sig = bitcoin::ecdsa::Signature {
			signature: secp.sign_ecdsa(&msg, &user_sk),
			sighash_type: EcdsaSighashType::All,
		};

		spending_tx.input[0].witness = build_refund_witness(&user_sig, &witness_script);

		// Verify the witness is correctly structured (3 items).
		assert_eq!(spending_tx.input[0].witness.len(), 3);
	}

	#[test]
	fn test_satisfaction_weight_cooperative() {
		let (_user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let witness_script = build_sip_witness_script(&user_pk, &server_pk, 2016);
		let weight = cooperative_spend_satisfaction_weight(&witness_script);
		// Weight should be reasonable (> 0, < 1000 WU).
		assert!(weight > Weight::ZERO);
		assert!(weight < Weight::from_wu(1000));
	}

	#[test]
	fn test_satisfaction_weight_refund() {
		let (_user_sk, user_pk, _server_sk, server_pk) = test_keys();
		let witness_script = build_sip_witness_script(&user_pk, &server_pk, 2016);
		let weight = refund_spend_satisfaction_weight(&witness_script);
		// Weight should be reasonable and less than cooperative (fewer sig items).
		assert!(weight > Weight::ZERO);
		let coop_weight = cooperative_spend_satisfaction_weight(&witness_script);
		assert!(weight < coop_weight);
	}
}
