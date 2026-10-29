// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains peer state objects that are used by `LSPS2ServiceHandler`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::lsps0::ser::LSPSRequestId;
use crate::lsps2::msgs::LSPS2OpeningFeeParams;
use crate::lsps2::msgs::LSPS2Request;
use crate::lsps2::payment_queue::{InterceptedHTLC, PaymentQueue};
use crate::lsps2::utils::{compute_opening_fee, is_expired_opening_fee_params};
use crate::prelude::{new_hash_map, HashMap};

use lightning::ln::msgs::{ErrorAction, LightningError};
use lightning::ln::types::ChannelId;
use lightning::util::logger::Level;
use lightning::{impl_ser_tlv_based, impl_ser_tlv_based_enum};

use bitcoin::Transaction;

/// Information about the initial payment size and JIT channel opening fee.
/// This will be provided in the `OpenChannel` event.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct OpenChannelParams {
	pub(super) opening_fee_msat: u64,
	pub(super) amt_to_forward_msat: u64,
}

/// A payment that will be forwarded while skimming the given JIT channel opening fee.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct FeePayment {
	pub(super) htlcs: Vec<InterceptedHTLC>,
	pub(super) opening_fee_msat: u64,
}

#[derive(Debug)]
pub(super) struct ChannelStateError(pub(super) String);

impl From<ChannelStateError> for LightningError {
	fn from(value: ChannelStateError) -> Self {
		LightningError { err: value.0, action: ErrorAction::IgnoreAndLog(Level::Info) }
	}
}

/// Possible actions that need to be taken when an HTLC is intercepted.
#[derive(Debug, PartialEq)]
pub(super) enum HTLCInterceptedAction {
	/// The opening of the JIT channel.
	OpenChannel(OpenChannelParams),
	/// The forwarding of the intercepted HTLC.
	ForwardHTLC(ChannelId),
	ForwardPayment(ChannelId, FeePayment),
}

/// The forwarding of a payment while skimming the JIT channel opening fee.
#[derive(Debug, PartialEq)]
pub(super) struct ForwardPaymentAction(pub(super) ChannelId, pub(super) FeePayment);

/// The forwarding of previously intercepted HTLCs without skimming any further fees.
#[derive(Debug, PartialEq)]
pub(super) struct ForwardHTLCsAction(pub(super) ChannelId, pub(super) Vec<InterceptedHTLC>);

#[derive(Debug, Clone)]
pub(super) enum TrustModel {
	ClientTrustsLsp { funding_tx_broadcast_safe: bool, funding_tx: Option<Transaction> },
	LspTrustsClient,
}

impl TrustModel {
	pub(super) fn should_manually_broadcast(&self, state_is_payment_forward: bool) -> bool {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx_broadcast_safe, funding_tx } => {
				*funding_tx_broadcast_safe && state_is_payment_forward && funding_tx.is_some()
			},
			// in lsp-trusts-client, the broadcast is automatic, so we never need to manually broadcast.
			TrustModel::LspTrustsClient => false,
		}
	}

	pub(super) fn new(client_trusts_lsp: bool) -> Self {
		if client_trusts_lsp {
			TrustModel::ClientTrustsLsp { funding_tx_broadcast_safe: false, funding_tx: None }
		} else {
			TrustModel::LspTrustsClient
		}
	}

	pub(super) fn set_funding_tx(&mut self, funding_tx: Transaction) {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx: tx, .. } => {
				*tx = Some(funding_tx);
			},
			TrustModel::LspTrustsClient => {
				// No-op
			},
		}
	}

	pub(super) fn set_funding_tx_broadcast_safe(&mut self, funding_tx_broadcast_safe: bool) {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx_broadcast_safe: safe, .. } => {
				*safe = funding_tx_broadcast_safe;
			},
			TrustModel::LspTrustsClient => {
				// No-op
			},
		}
	}

	pub(super) fn get_funding_tx(&self) -> Option<&Transaction> {
		match self {
			TrustModel::ClientTrustsLsp { funding_tx, .. } => funding_tx.as_ref(),
			_ => None,
		}
	}

	pub(super) fn is_client_trusts_lsp(&self) -> bool {
		match self {
			TrustModel::ClientTrustsLsp { .. } => true,
			TrustModel::LspTrustsClient => false,
		}
	}
}

impl_ser_tlv_based_enum!(TrustModel,
	(0, ClientTrustsLsp) => {
		(0, funding_tx_broadcast_safe, required),
		(2, funding_tx, option),
	},
	(2, LspTrustsClient) => {
	},
);

/// The different states a requested JIT channel can be in.
#[derive(Debug)]
pub(super) enum OutboundJITChannelState {
	/// The JIT channel SCID was created after a buy request, and we are awaiting an initial payment
	/// of sufficient size to open the channel.
	PendingInitialPayment { payment_queue: PaymentQueue },
	/// An initial payment of sufficient size was intercepted to the JIT channel SCID, triggering the
	/// opening of the channel. We are awaiting the completion of the channel establishment.
	PendingChannelOpen { payment_queue: PaymentQueue, opening_fee_msat: u64 },
	/// The channel is open and a payment was forwarded while skimming the JIT channel fee.
	/// No further payments can be forwarded until the pending payment succeeds or fails, as we need
	/// to know whether the JIT channel fee needs to be skimmed from a next payment or not.
	PendingPaymentForward {
		payment_queue: PaymentQueue,
		opening_fee_msat: u64,
		channel_id: ChannelId,
	},
	/// The channel is open, no payment is currently being forwarded, and the JIT channel fee still
	/// needs to be paid. This state can occur when the initial payment fails, e.g. due to a
	/// prepayment probe. We are awaiting a next payment of sufficient size to forward and skim the
	/// JIT channel fee.
	PendingPayment { payment_queue: PaymentQueue, opening_fee_msat: u64, channel_id: ChannelId },
	/// The channel is open and a payment was successfully forwarded while skimming the JIT channel
	/// fee. Any subsequent HTLCs can be forwarded without additional logic.
	PaymentForwarded { channel_id: ChannelId },
}

impl OutboundJITChannelState {
	pub(super) fn new() -> Self {
		OutboundJITChannelState::PendingInitialPayment { payment_queue: PaymentQueue::new() }
	}

	pub(super) fn htlc_intercepted(
		&mut self, opening_fee_params: &LSPS2OpeningFeeParams, payment_size_msat: &Option<u64>,
		htlc: InterceptedHTLC,
	) -> Result<Option<HTLCInterceptedAction>, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingInitialPayment { payment_queue } => {
				let (total_expected_outbound_amount_msat, num_htlcs) = payment_queue.add_htlc(htlc);

				let (expected_payment_size_msat, mpp_mode) =
					if let Some(payment_size_msat) = payment_size_msat {
						(*payment_size_msat, true)
					} else {
						debug_assert_eq!(num_htlcs, 1);
						if num_htlcs != 1 {
							return Err(ChannelStateError(
								"Paying via multiple HTLCs is disallowed in \"no-MPP+var-invoice\" mode.".to_string()
							));
						}
						(total_expected_outbound_amount_msat, false)
					};

				if expected_payment_size_msat < opening_fee_params.min_payment_size_msat
					|| expected_payment_size_msat > opening_fee_params.max_payment_size_msat
				{
					return Err(ChannelStateError(
							format!("Payment size violates our limits: expected_payment_size_msat = {}, min_payment_size_msat = {}, max_payment_size_msat = {}",
									expected_payment_size_msat,
									opening_fee_params.min_payment_size_msat,
									opening_fee_params.max_payment_size_msat
							)));
				}

				let opening_fee_msat = compute_opening_fee(
					expected_payment_size_msat,
					opening_fee_params.min_fee_msat,
					opening_fee_params.proportional.into(),
				).ok_or(ChannelStateError(
					format!("Could not compute valid opening fee with min_fee_msat = {}, proportional = {}, and expected_payment_size_msat = {}",
						opening_fee_params.min_fee_msat,
						opening_fee_params.proportional,
						expected_payment_size_msat
					))
				)?;

				let amt_to_forward_msat =
					expected_payment_size_msat.saturating_sub(opening_fee_msat);

				// Go ahead and open the channel if we intercepted sufficient HTLCs.
				if total_expected_outbound_amount_msat >= expected_payment_size_msat
					&& amt_to_forward_msat > 0
				{
					*self = OutboundJITChannelState::PendingChannelOpen {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat,
					};
					let open_channel = HTLCInterceptedAction::OpenChannel(OpenChannelParams {
						opening_fee_msat,
						amt_to_forward_msat,
					});
					Ok(Some(open_channel))
				} else {
					if mpp_mode {
						*self = OutboundJITChannelState::PendingInitialPayment {
							payment_queue: core::mem::take(payment_queue),
						};
						Ok(None)
					} else {
						Err(ChannelStateError(
							"Intercepted HTLC is too small to pay opening fee".to_string(),
						))
					}
				}
			},
			OutboundJITChannelState::PendingChannelOpen { payment_queue, opening_fee_msat } => {
				let mut payment_queue = core::mem::take(payment_queue);
				payment_queue.add_htlc(htlc);
				*self = OutboundJITChannelState::PendingChannelOpen {
					payment_queue,
					opening_fee_msat: *opening_fee_msat,
				};
				Ok(None)
			},
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue = core::mem::take(payment_queue);
				payment_queue.add_htlc(htlc);
				*self = OutboundJITChannelState::PendingPaymentForward {
					payment_queue,
					opening_fee_msat: *opening_fee_msat,
					channel_id: *channel_id,
				};
				Ok(None)
			},
			OutboundJITChannelState::PendingPayment {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				let mut payment_queue = core::mem::take(payment_queue);
				payment_queue.add_htlc(htlc);
				if let Some(entry) = payment_queue.pop_greater_than_msat(*opening_fee_msat) {
					let forward_payment = HTLCInterceptedAction::ForwardPayment(
						*channel_id,
						FeePayment { htlcs: entry.htlcs, opening_fee_msat: *opening_fee_msat },
					);
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue,
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(Some(forward_payment))
				} else {
					*self = OutboundJITChannelState::PendingPayment {
						payment_queue,
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(None)
				}
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				let forward = HTLCInterceptedAction::ForwardHTLC(*channel_id);
				*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok(Some(forward))
			},
		}
	}

	pub(super) fn channel_ready(
		&mut self, channel_id: ChannelId,
	) -> Result<ForwardPaymentAction, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingChannelOpen { payment_queue, opening_fee_msat } => {
				if let Some(entry) = payment_queue.pop_greater_than_msat(*opening_fee_msat) {
					let forward_payment = ForwardPaymentAction(
						channel_id,
						FeePayment { htlcs: entry.htlcs, opening_fee_msat: *opening_fee_msat },
					);
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id,
					};
					Ok(forward_payment)
				} else {
					return Err(ChannelStateError(
						"No forwardable payment available when moving to channel ready."
							.to_string(),
					));
				}
			},
			state => Err(ChannelStateError(format!(
				"Channel ready received when JIT Channel was in state: {:?}",
				state
			))),
		}
	}

	pub(super) fn htlc_handling_failed(
		&mut self,
	) -> Result<Option<ForwardPaymentAction>, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				if let Some(entry) = payment_queue.pop_greater_than_msat(*opening_fee_msat) {
					let forward_payment = ForwardPaymentAction(
						*channel_id,
						FeePayment { htlcs: entry.htlcs, opening_fee_msat: *opening_fee_msat },
					);
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(Some(forward_payment))
				} else {
					*self = OutboundJITChannelState::PendingPayment {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(None)
				}
			},
			OutboundJITChannelState::PendingPayment {
				payment_queue,
				opening_fee_msat,
				channel_id,
			} => {
				*self = OutboundJITChannelState::PendingPayment {
					payment_queue: core::mem::take(payment_queue),
					opening_fee_msat: *opening_fee_msat,
					channel_id: *channel_id,
				};
				Ok(None)
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok(None)
			},
			state => Err(ChannelStateError(format!(
				"HTLC handling failed when JIT Channel was in state: {:?}",
				state
			))),
		}
	}

	pub(super) fn payment_forwarded(
		&mut self, skimmed_fee_msat: u64,
	) -> Result<Option<ForwardHTLCsAction>, ChannelStateError> {
		match self {
			OutboundJITChannelState::PendingPaymentForward {
				payment_queue,
				channel_id,
				opening_fee_msat,
			} => {
				if skimmed_fee_msat >= *opening_fee_msat {
					let mut pq = core::mem::take(payment_queue);
					let forward_htlcs = ForwardHTLCsAction(*channel_id, pq.clear());
					*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
					Ok(Some(forward_htlcs))
				} else {
					*self = OutboundJITChannelState::PendingPaymentForward {
						payment_queue: core::mem::take(payment_queue),
						opening_fee_msat: *opening_fee_msat,
						channel_id: *channel_id,
					};
					Ok(None)
				}
			},
			OutboundJITChannelState::PaymentForwarded { channel_id } => {
				*self = OutboundJITChannelState::PaymentForwarded { channel_id: *channel_id };
				Ok(None)
			},
			state => Err(ChannelStateError(format!(
				"Payment forwarded when JIT Channel was in state: {:?}",
				state
			))),
		}
	}
}

impl_ser_tlv_based_enum!(OutboundJITChannelState,
	(0, PendingInitialPayment) => {
		(0, payment_queue, required),
	},
	(2, PendingChannelOpen) => {
		(0, payment_queue, required),
		(2, opening_fee_msat, required),
	},
	(4, PendingPaymentForward) => {
		(0, payment_queue, required),
		(2, opening_fee_msat, required),
		(4, channel_id, required),
	},
	(6, PendingPayment) => {
		(0, payment_queue, required),
		(2, opening_fee_msat, required),
		(4, channel_id, required),
	},
	(8, PaymentForwarded) => {
		(0, channel_id, required),
	},
);

pub(super) struct OutboundJITChannel {
	pub(super) state: OutboundJITChannelState,
	pub(super) user_channel_id: u128,
	pub(super) opening_fee_params: LSPS2OpeningFeeParams,
	pub(super) payment_size_msat: Option<u64>,
	pub(super) trust_model: TrustModel,
}

impl_ser_tlv_based!(OutboundJITChannel, {
	(0, state, required),
	(2, user_channel_id, required),
	(4, opening_fee_params, required),
	(6, payment_size_msat, option),
	(8, trust_model, required),
});

impl OutboundJITChannel {
	pub(super) fn new(
		payment_size_msat: Option<u64>, opening_fee_params: LSPS2OpeningFeeParams,
		user_channel_id: u128, client_trusts_lsp: bool,
	) -> Self {
		Self {
			user_channel_id,
			state: OutboundJITChannelState::new(),
			opening_fee_params,
			payment_size_msat,
			trust_model: TrustModel::new(client_trusts_lsp),
		}
	}

	pub(super) fn htlc_intercepted(
		&mut self, htlc: InterceptedHTLC,
	) -> Result<Option<HTLCInterceptedAction>, LightningError> {
		let action =
			self.state.htlc_intercepted(&self.opening_fee_params, &self.payment_size_msat, htlc)?;
		Ok(action)
	}

	pub(super) fn htlc_handling_failed(
		&mut self,
	) -> Result<Option<ForwardPaymentAction>, LightningError> {
		let action = self.state.htlc_handling_failed()?;
		Ok(action)
	}

	pub(super) fn channel_ready(
		&mut self, channel_id: ChannelId,
	) -> Result<ForwardPaymentAction, LightningError> {
		let action = self.state.channel_ready(channel_id)?;
		Ok(action)
	}

	pub(super) fn payment_forwarded(
		&mut self, skimmed_fee_msat: u64,
	) -> Result<Option<ForwardHTLCsAction>, LightningError> {
		let action = self.state.payment_forwarded(skimmed_fee_msat)?;
		Ok(action)
	}

	pub(super) fn is_pending_initial_payment(&self) -> bool {
		matches!(self.state, OutboundJITChannelState::PendingInitialPayment { .. })
	}

	pub(super) fn is_prunable(&self) -> bool {
		// We deem an OutboundJITChannel prunable if our offer expired and we haven't intercepted
		// any HTLCs initiating the flow yet.
		let is_expired = is_expired_opening_fee_params(&self.opening_fee_params);
		self.is_pending_initial_payment() && is_expired
	}

	pub(super) fn set_funding_tx(&mut self, funding_tx: Transaction) {
		self.trust_model.set_funding_tx(funding_tx);
	}

	pub(super) fn set_funding_tx_broadcast_safe(&mut self, funding_tx_broadcast_safe: bool) {
		self.trust_model.set_funding_tx_broadcast_safe(funding_tx_broadcast_safe);
	}

	pub(super) fn should_broadcast_funding_transaction(&self) -> bool {
		self.trust_model.should_manually_broadcast(matches!(
			self.state,
			OutboundJITChannelState::PaymentForwarded { .. }
		))
	}

	pub(super) fn get_channel_id(&self) -> Option<ChannelId> {
		match self.state {
			OutboundJITChannelState::PaymentForwarded { channel_id } => Some(channel_id),
			_ => None,
		}
	}

	pub(super) fn get_funding_tx(&self) -> Option<&Transaction> {
		self.trust_model.get_funding_tx()
	}

	pub(super) fn is_client_trusts_lsp(&self) -> bool {
		self.trust_model.is_client_trusts_lsp()
	}
}

pub(crate) struct PeerState {
	pub(super) outbound_channels_by_intercept_scid: HashMap<u64, OutboundJITChannel>,
	pub(super) intercept_scid_by_user_channel_id: HashMap<u128, u64>,
	pub(super) intercept_scid_by_channel_id: HashMap<ChannelId, u64>,
	pub(super) pending_requests: HashMap<LSPSRequestId, LSPS2Request>,
	pub(super) needs_persist: bool,
}

impl PeerState {
	pub(super) fn new() -> Self {
		let outbound_channels_by_intercept_scid = new_hash_map();
		let pending_requests = new_hash_map();
		let intercept_scid_by_user_channel_id = new_hash_map();
		let intercept_scid_by_channel_id = new_hash_map();
		let needs_persist = false;
		Self {
			outbound_channels_by_intercept_scid,
			pending_requests,
			intercept_scid_by_user_channel_id,
			intercept_scid_by_channel_id,
			needs_persist,
		}
	}

	pub(super) fn insert_outbound_channel(
		&mut self, intercept_scid: u64, channel: OutboundJITChannel,
	) {
		self.outbound_channels_by_intercept_scid.insert(intercept_scid, channel);
		self.needs_persist |= true;
	}

	pub(super) fn prune_pending_requests(&mut self) {
		self.pending_requests.retain(|_, entry| {
			match entry {
				LSPS2Request::GetInfo(_) => false,
				LSPS2Request::Buy(request) => {
					// Prune any expired buy requests.
					!is_expired_opening_fee_params(&request.opening_fee_params)
				},
			}
		});
	}

	pub(super) fn prune_expired_request_state(&mut self) {
		self.outbound_channels_by_intercept_scid.retain(|intercept_scid, entry| {
			if entry.is_prunable() {
				// We abort the flow, and prune any data kept.
				self.intercept_scid_by_channel_id.retain(|_, iscid| intercept_scid != iscid);
				self.intercept_scid_by_user_channel_id.retain(|_, iscid| intercept_scid != iscid);
				self.needs_persist |= true;
				return false;
			}
			true
		});
	}

	pub(super) fn remove_terminal_channel_state(&mut self, channel_id: ChannelId) -> Option<u64> {
		let intercept_scid = self.intercept_scid_by_channel_id.get(&channel_id).copied()?;
		let should_remove = self
			.outbound_channels_by_intercept_scid
			.get(&intercept_scid)
			.and_then(|entry| entry.get_channel_id())
			.is_some_and(|existing_channel_id| existing_channel_id == channel_id);

		if !should_remove {
			return None;
		}

		self.outbound_channels_by_intercept_scid.remove(&intercept_scid);
		self.intercept_scid_by_channel_id.remove(&channel_id);
		self.intercept_scid_by_user_channel_id.retain(|_, iscid| *iscid != intercept_scid);
		self.needs_persist = true;

		Some(intercept_scid)
	}

	pub(super) fn pending_requests_and_channels(&self) -> usize {
		let pending_requests = self.pending_requests.len();
		let pending_outbound_channels = self
			.outbound_channels_by_intercept_scid
			.iter()
			.filter(|(_, v)| v.is_pending_initial_payment())
			.count();
		pending_requests + pending_outbound_channels
	}

	pub(super) fn is_prunable(&self) -> bool {
		// Return whether the entire state is empty.
		self.pending_requests.is_empty() && self.outbound_channels_by_intercept_scid.is_empty()
	}
}

impl_ser_tlv_based!(PeerState, {
	(0, outbound_channels_by_intercept_scid, required),
	(2, intercept_scid_by_user_channel_id, required),
	(4, intercept_scid_by_channel_id, required),
	(_unused, pending_requests, (static_value, new_hash_map())),
	(_unused, needs_persist, (static_value, false)),
});

#[cfg(test)]
mod tests {
	use super::*;

	use crate::lsps0::ser::LSPSDateTime;

	use bitcoin::{absolute::LockTime, transaction::Version};
	use core::str::FromStr;
	use lightning::io::Cursor;
	use lightning::ln::channelmanager::InterceptId;
	use lightning::util::ser::{Readable, Writeable};

	use lightning_types::payment::PaymentHash;

	#[test]
	fn test_jit_channel_state_mpp() {
		let payment_size_msat = Some(500_000_000);
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let mut state = OutboundJITChannelState::new();
		// Intercepts the first HTLC of a multipart payment A.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([0; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingInitialPayment { .. }));
			assert!(action.is_none());
		}
		// Intercepts the first HTLC of a different multipart payment B.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([1; 32]),
						expected_outbound_amount_msat: 1_000_000,
						payment_hash: PaymentHash([101; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingInitialPayment { .. }));
			assert!(action.is_none());
		}
		// Intercepts the second HTLC of multipart payment A, completing the expected payment and
		// opening the channel.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([2; 32]),
						expected_outbound_amount_msat: 300_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(matches!(action, Some(HTLCInterceptedAction::OpenChannel(_))));
		}
		// Channel opens, becomes ready, and multipart payment A gets forwarded.
		{
			let ForwardPaymentAction(channel_id, payment) =
				state.channel_ready(ChannelId([200; 32])).unwrap();
			assert_eq!(channel_id, ChannelId([200; 32]));
			assert_eq!(payment.opening_fee_msat, 10_000_000);
			assert_eq!(
				payment.htlcs,
				vec![
					InterceptedHTLC {
						intercept_id: InterceptId([0; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
					InterceptedHTLC {
						intercept_id: InterceptId([2; 32]),
						expected_outbound_amount_msat: 300_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				]
			);
		}
		// Intercepts the first HTLC of a different payment C.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([3; 32]),
						expected_outbound_amount_msat: 2_000_000,
						payment_hash: PaymentHash([102; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
			assert!(action.is_none());
		}
		// Payment A fails.
		{
			let action = state.htlc_handling_failed().unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPayment { .. }));
			// No payments have received sufficient HTLCs yet.
			assert!(action.is_none());
		}
		// Additional HTLC of payment B arrives, completing the expectd payment.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([4; 32]),
						expected_outbound_amount_msat: 500_000_000,
						payment_hash: PaymentHash([101; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
			match action {
				Some(HTLCInterceptedAction::ForwardPayment(channel_id, payment)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(payment.opening_fee_msat, 10_000_000);
					assert_eq!(
						payment.htlcs,
						vec![
							InterceptedHTLC {
								intercept_id: InterceptId([1; 32]),
								expected_outbound_amount_msat: 1_000_000,
								payment_hash: PaymentHash([101; 32]),
							},
							InterceptedHTLC {
								intercept_id: InterceptId([4; 32]),
								expected_outbound_amount_msat: 500_000_000,
								payment_hash: PaymentHash([101; 32]),
							},
						]
					);
				},
				_ => panic!("Unexpected action when intercepted HTLC."),
			}
		}
		// Payment completes, queued payments get forwarded.
		{
			let action = state.payment_forwarded(100000000000).unwrap();
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
			match action {
				Some(ForwardHTLCsAction(channel_id, htlcs)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(
						htlcs,
						vec![InterceptedHTLC {
							intercept_id: InterceptId([3; 32]),
							expected_outbound_amount_msat: 2_000_000,
							payment_hash: PaymentHash([102; 32]),
						}]
					);
				},
				_ => panic!("Unexpected action when forwarded payment."),
			}
		}
		// Any new HTLC gets automatically forwarded.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([5; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([103; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
			assert!(
				matches!(action, Some(HTLCInterceptedAction::ForwardHTLC(channel_id)) if channel_id == ChannelId([200; 32]))
			);
		}
	}

	#[test]
	fn test_jit_channel_state_no_mpp() {
		let payment_size_msat = None;
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let mut state = OutboundJITChannelState::new();
		// Intercepts payment A, opening the channel.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([0; 32]),
						expected_outbound_amount_msat: 500_000_000,
						payment_hash: PaymentHash([100; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(matches!(action, Some(HTLCInterceptedAction::OpenChannel(_))));
		}
		// Intercepts payment B.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([1; 32]),
						expected_outbound_amount_msat: 600_000_000,
						payment_hash: PaymentHash([101; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingChannelOpen { .. }));
			assert!(action.is_none());
		}
		// Channel opens, becomes ready, and payment A gets forwarded.
		{
			let ForwardPaymentAction(channel_id, payment) =
				state.channel_ready(ChannelId([200; 32])).unwrap();
			assert_eq!(channel_id, ChannelId([200; 32]));
			assert_eq!(payment.opening_fee_msat, 10_000_000);
			assert_eq!(
				payment.htlcs,
				vec![InterceptedHTLC {
					intercept_id: InterceptId([0; 32]),
					expected_outbound_amount_msat: 500_000_000,
					payment_hash: PaymentHash([100; 32]),
				},]
			);
		}
		// Intercepts payment C.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([2; 32]),
						expected_outbound_amount_msat: 500_000_000,
						payment_hash: PaymentHash([102; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
			assert!(action.is_none());
		}
		// Payment A fails, and payment B is forwarded.
		{
			let action = state.htlc_handling_failed().unwrap();
			assert!(matches!(state, OutboundJITChannelState::PendingPaymentForward { .. }));
			match action {
				Some(ForwardPaymentAction(channel_id, payment)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(
						payment.htlcs,
						vec![InterceptedHTLC {
							intercept_id: InterceptId([1; 32]),
							expected_outbound_amount_msat: 600_000_000,
							payment_hash: PaymentHash([101; 32]),
						},]
					);
				},
				_ => panic!("Unexpected action when HTLC handling failed."),
			}
		}
		// Payment completes, queued payments get forwarded.
		{
			let action = state.payment_forwarded(10000000000).unwrap();
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
			match action {
				Some(ForwardHTLCsAction(channel_id, htlcs)) => {
					assert_eq!(channel_id, ChannelId([200; 32]));
					assert_eq!(
						htlcs,
						vec![InterceptedHTLC {
							intercept_id: InterceptId([2; 32]),
							expected_outbound_amount_msat: 500_000_000,
							payment_hash: PaymentHash([102; 32]),
						}]
					);
				},
				_ => panic!("Unexpected action when forwarded payment."),
			}
		}
		// Any new HTLC gets automatically forwarded.
		{
			let action = state
				.htlc_intercepted(
					&opening_fee_params,
					&payment_size_msat,
					InterceptedHTLC {
						intercept_id: InterceptId([3; 32]),
						expected_outbound_amount_msat: 200_000_000,
						payment_hash: PaymentHash([103; 32]),
					},
				)
				.unwrap();
			assert!(matches!(state, OutboundJITChannelState::PaymentForwarded { .. }));
			assert!(
				matches!(action, Some(HTLCInterceptedAction::ForwardHTLC(channel_id)) if channel_id == ChannelId([200; 32]))
			);
		}
	}

	#[test]
	fn replayed_intercepted_htlc_after_persist_is_idempotent() {
		let payment_size_msat = Some(500_000_000);
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let intercept_scid = 42;
		let user_channel_id = 43;
		let htlc = InterceptedHTLC {
			intercept_id: InterceptId([1; 32]),
			expected_outbound_amount_msat: 500_000_000,
			payment_hash: PaymentHash([2; 32]),
		};

		let mut jit_channel =
			OutboundJITChannel::new(payment_size_msat, opening_fee_params, user_channel_id, false);
		assert!(matches!(
			jit_channel.htlc_intercepted(htlc).unwrap(),
			Some(HTLCInterceptedAction::OpenChannel(_))
		));

		let mut peer_state = PeerState::new();
		peer_state.intercept_scid_by_user_channel_id.insert(user_channel_id, intercept_scid);
		peer_state.insert_outbound_channel(intercept_scid, jit_channel);

		let encoded_peer_state = peer_state.encode();
		let mut decoded_peer_state = PeerState::read(&mut Cursor::new(encoded_peer_state)).unwrap();
		let decoded_jit_channel = decoded_peer_state
			.outbound_channels_by_intercept_scid
			.get_mut(&intercept_scid)
			.unwrap();

		assert!(decoded_jit_channel.htlc_intercepted(htlc).unwrap().is_none());

		let ForwardPaymentAction(_, fee_payment) =
			decoded_jit_channel.channel_ready(ChannelId([3; 32])).unwrap();
		assert_eq!(fee_payment.htlcs, vec![htlc]);
	}

	#[test]
	fn removes_terminal_state_for_closed_channel() {
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat: 10_000_000,
			proportional: 10_000,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 4032,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10_000_000,
			max_payment_size_msat: 1_000_000_000,
			promise: "ignore".to_string(),
		};
		let stale_intercept_scid = 42;
		let stale_user_channel_id = 43;
		let stale_channel_id = ChannelId([44; 32]);
		let live_intercept_scid = 45;
		let live_user_channel_id = 46;
		let live_channel_id = ChannelId([47; 32]);

		let mut stale_jit_channel =
			OutboundJITChannel::new(None, opening_fee_params.clone(), stale_user_channel_id, false);
		stale_jit_channel.state =
			OutboundJITChannelState::PaymentForwarded { channel_id: stale_channel_id };
		let mut live_jit_channel =
			OutboundJITChannel::new(None, opening_fee_params, live_user_channel_id, false);
		live_jit_channel.state =
			OutboundJITChannelState::PaymentForwarded { channel_id: live_channel_id };

		let mut peer_state = PeerState::new();
		peer_state.insert_outbound_channel(stale_intercept_scid, stale_jit_channel);
		peer_state.insert_outbound_channel(live_intercept_scid, live_jit_channel);
		peer_state
			.intercept_scid_by_user_channel_id
			.insert(stale_user_channel_id, stale_intercept_scid);
		peer_state
			.intercept_scid_by_user_channel_id
			.insert(live_user_channel_id, live_intercept_scid);
		peer_state.intercept_scid_by_channel_id.insert(stale_channel_id, stale_intercept_scid);
		peer_state.intercept_scid_by_channel_id.insert(live_channel_id, live_intercept_scid);
		peer_state.needs_persist = false;

		assert_eq!(
			peer_state.remove_terminal_channel_state(stale_channel_id),
			Some(stale_intercept_scid)
		);
		assert!(!peer_state
			.outbound_channels_by_intercept_scid
			.contains_key(&stale_intercept_scid));
		assert!(peer_state.outbound_channels_by_intercept_scid.contains_key(&live_intercept_scid));
		assert!(!peer_state.intercept_scid_by_user_channel_id.contains_key(&stale_user_channel_id));
		assert_eq!(
			peer_state.intercept_scid_by_user_channel_id.get(&live_user_channel_id),
			Some(&live_intercept_scid)
		);
		assert!(!peer_state.intercept_scid_by_channel_id.contains_key(&stale_channel_id));
		assert_eq!(
			peer_state.intercept_scid_by_channel_id.get(&live_channel_id),
			Some(&live_intercept_scid)
		);
		assert!(peer_state.needs_persist);

		peer_state.needs_persist = false;
		assert_eq!(peer_state.remove_terminal_channel_state(stale_channel_id), None);
		assert!(!peer_state.needs_persist);
	}

	#[test]
	fn broadcast_not_allowed_after_non_paying_fee_payment_claimed() {
		let min_fee_msat: u64 = 12345;
		let opening_fee_params = LSPS2OpeningFeeParams {
			min_fee_msat,
			proportional: 0,
			valid_until: LSPSDateTime::from_str("2035-05-20T08:30:45Z").unwrap(),
			min_lifetime: 144,
			max_client_to_self_delay: 128,
			min_payment_size_msat: 1,
			max_payment_size_msat: 10_000_000_000,
			promise: "ignore".to_string(),
		};

		let payment_size_msat = Some(1_000_000);
		let user_channel_id = 4242u128;
		let mut jit_channel = OutboundJITChannel::new(
			payment_size_msat,
			opening_fee_params.clone(),
			user_channel_id,
			true,
		);

		let opening_payment_hash = PaymentHash([42; 32]);
		let htlcs_for_opening = [
			InterceptedHTLC {
				intercept_id: InterceptId([0; 32]),
				expected_outbound_amount_msat: 400_000,
				payment_hash: opening_payment_hash,
			},
			InterceptedHTLC {
				intercept_id: InterceptId([1; 32]),
				expected_outbound_amount_msat: 600_000,
				payment_hash: opening_payment_hash,
			},
		];

		assert!(jit_channel.htlc_intercepted(htlcs_for_opening[0].clone()).unwrap().is_none());
		let action = jit_channel.htlc_intercepted(htlcs_for_opening[1].clone()).unwrap();
		match action {
			Some(HTLCInterceptedAction::OpenChannel(_)) => {},
			other => panic!("Expected OpenChannel action, got {:?}", other),
		}

		let channel_id = ChannelId([7; 32]);
		let ForwardPaymentAction(_, fee_payment) = jit_channel.channel_ready(channel_id).unwrap();
		assert_eq!(fee_payment.opening_fee_msat, min_fee_msat);

		let followup = jit_channel.htlc_handling_failed().unwrap();
		assert!(followup.is_none());

		let dummy_tx = Transaction {
			version: Version(2),
			lock_time: LockTime::ZERO,
			input: vec![],
			output: vec![],
		};
		jit_channel.set_funding_tx(dummy_tx);
		jit_channel.set_funding_tx_broadcast_safe(true);
		assert!(
			!jit_channel.should_broadcast_funding_transaction(),
			"Should not broadcast before any successful payment is claimed"
		);

		let second_payment_hash = PaymentHash([99; 32]);
		let second_htlc = InterceptedHTLC {
			intercept_id: InterceptId([2; 32]),
			expected_outbound_amount_msat: min_fee_msat,
			payment_hash: second_payment_hash,
		};
		let action2 = jit_channel.htlc_intercepted(second_htlc).unwrap();
		let (forwarded_channel_id, fee_payment2) = match action2 {
			Some(HTLCInterceptedAction::ForwardPayment(cid, fp)) => (cid, fp),
			other => panic!("Expected ForwardPayment for second HTLC, got {:?}", other),
		};
		assert_eq!(forwarded_channel_id, channel_id);
		assert_eq!(fee_payment2.opening_fee_msat, min_fee_msat);

		assert!(
			!jit_channel.should_broadcast_funding_transaction(),
			"Should not broadcast before any successful payment is claimed"
		);

		// Forward a payment that is not enough to cover the fees
		let _ = jit_channel.payment_forwarded(min_fee_msat - 1).unwrap();

		assert!(
			!jit_channel.should_broadcast_funding_transaction(),
			"Should not broadcast before all the fees are collected"
		);

		let _ = jit_channel.payment_forwarded(min_fee_msat).unwrap();

		let broadcast_allowed = jit_channel.should_broadcast_funding_transaction();

		assert!(
			broadcast_allowed,
			"Broadcast was not allowed even though all the skimmed fees were collected"
		);
	}
}
