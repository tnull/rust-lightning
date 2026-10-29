// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains peer state objects that are used by `LSPS5ServiceHandler`.

use super::msgs::{LSPS5AppName, LSPS5WebhookUrl};
use super::service::{MIN_WEBHOOK_RETENTION_DAYS, NOTIFICATION_COOLDOWN_RESET_INTERVAL};

use crate::lsps0::ser::LSPSDateTime;
use crate::peer_state::PrunablePeerState;
use crate::prelude::HashSet;

use lightning::impl_ser_tlv_based;

use bitcoin::secp256k1::PublicKey;

use alloc::vec::Vec;

/// A stored webhook.
#[derive(Debug, Clone)]
pub(super) struct Webhook {
	pub(super) _app_name: LSPS5AppName,
	pub(super) url: LSPS5WebhookUrl,
	pub(super) _counterparty_node_id: PublicKey,
	// Timestamp used for tracking when the webhook was created / updated, or when the last notification was sent.
	// This is used to determine if the webhook is stale and should be pruned.
	pub(super) last_used: LSPSDateTime,
	// Timestamp when we last sent a notification to the client. This enforces the notification
	// cooldown that protects the client from repeated spammy wake-ups.
	pub(super) last_notification_sent: Option<LSPSDateTime>,
}

impl_ser_tlv_based!(Webhook, {
	(0, _app_name, required),
	(2, url, required),
	(4, _counterparty_node_id, required),
	(6, last_used, required),
	(8, last_notification_sent, option),
});

#[derive(Debug)]
pub(crate) struct PeerState {
	pub(super) webhooks: Vec<(LSPS5AppName, Webhook)>,
	// Timestamp of the last peer lifecycle event that was allowed to clear notification cooldowns.
	// This is not the notification cooldown itself: `last_notification_sent` protects clients from
	// repeated wake-ups, while this protects registered notification URLs from amplification via
	// rapid connection churn.
	pub(super) last_notification_cooldown_reset: Option<LSPSDateTime>,
}

impl PeerState {
	pub(super) fn webhook_mut(&mut self, name: &LSPS5AppName) -> Option<&mut Webhook> {
		self.webhooks.iter_mut().find_map(|(n, h)| if n == name { Some(h) } else { None })
	}

	pub(super) fn webhooks(&self) -> &Vec<(LSPS5AppName, Webhook)> {
		&self.webhooks
	}

	pub(super) fn webhooks_mut(&mut self) -> &mut Vec<(LSPS5AppName, Webhook)> {
		&mut self.webhooks
	}

	pub(super) fn webhooks_len(&self) -> usize {
		self.webhooks.len()
	}

	pub(super) fn app_names(&self) -> Vec<LSPS5AppName> {
		self.webhooks.iter().map(|(n, _)| n).cloned().collect()
	}

	pub(super) fn insert_webhook(&mut self, name: LSPS5AppName, hook: Webhook) {
		for (n, h) in self.webhooks.iter_mut() {
			if *n == name {
				*h = hook;
				return;
			}
		}

		self.webhooks.push((name, hook));
	}

	pub(super) fn remove_webhook(&mut self, name: &LSPS5AppName) -> bool {
		let mut removed = false;
		self.webhooks.retain(|(n, _)| {
			if n != name {
				true
			} else {
				removed = true;
				false
			}
		});
		removed
	}

	// Returns whether the cooldowns were reset.
	pub(super) fn reset_notification_cooldown(&mut self, now: LSPSDateTime) -> bool {
		let can_reset = self.last_notification_cooldown_reset.as_ref().map_or(true, |last_reset| {
			now.duration_since(last_reset) >= NOTIFICATION_COOLDOWN_RESET_INTERVAL
		});
		if !can_reset {
			return false;
		}

		for (_, h) in self.webhooks.iter_mut() {
			h.last_notification_sent = None;
		}
		self.last_notification_cooldown_reset = Some(now);
		true
	}
}

impl Default for PeerState {
	fn default() -> Self {
		let webhooks = Vec::new();
		let last_notification_cooldown_reset = None;
		Self { webhooks, last_notification_cooldown_reset }
	}
}

impl_ser_tlv_based!(PeerState, {
	(0, webhooks, required_vec),
	(_unused, last_notification_cooldown_reset, (static_value, None::<LSPSDateTime>)),
});

pub(crate) struct PruneContext {
	/// The current time if stale webhooks are due to be pruned.
	pub(super) now: Option<LSPSDateTime>,
	/// Clients we have a usable channel with, whose state is retained even without webhooks.
	pub(super) peers_with_open_channel: HashSet<PublicKey>,
}

impl PrunablePeerState for PeerState {
	type PruneContext = PruneContext;

	fn prune_expired(&mut self, _counterparty_node_id: &PublicKey, ctx: &mut PruneContext) -> bool {
		let now = match ctx.now {
			Some(now) => now,
			None => return false,
		};
		let num_webhooks = self.webhooks.len();
		self.webhooks.retain(|(_, webhook)| {
			now.duration_since(&webhook.last_used) < MIN_WEBHOOK_RETENTION_DAYS
		});
		self.webhooks.len() != num_webhooks
	}

	fn is_prunable(&self, counterparty_node_id: &PublicKey, ctx: &PruneContext) -> bool {
		self.webhooks.is_empty() && !ctx.peers_with_open_channel.contains(counterparty_node_id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::alloc::string::ToString;
	use crate::tests::utils::parse_pubkey;

	use core::time::Duration;

	fn lsps_datetime(seconds: u64) -> LSPSDateTime {
		LSPSDateTime::new_from_duration_since_epoch(Duration::from_secs(seconds))
	}

	fn lsps_datetime_millis(milliseconds: u64) -> LSPSDateTime {
		LSPSDateTime::new_from_duration_since_epoch(Duration::from_millis(milliseconds))
	}

	fn test_webhook(last_notification_sent: Option<LSPSDateTime>) -> (LSPS5AppName, Webhook) {
		let app_name = LSPS5AppName::new("test_app".to_string()).unwrap();
		let url = LSPS5WebhookUrl::new("https://example.com/webhook".to_string()).unwrap();
		let counterparty_node_id =
			parse_pubkey("02c0ded160a4a70d71058509b647949a938924d3a6e109c6eb6aee8e2bb27dc79c")
				.unwrap();
		let webhook = Webhook {
			_app_name: app_name.clone(),
			url,
			_counterparty_node_id: counterparty_node_id,
			last_used: lsps_datetime(1_000),
			last_notification_sent,
		};
		(app_name, webhook)
	}

	fn test_peer_state(last_notification_sent: Option<LSPSDateTime>) -> PeerState {
		PeerState {
			webhooks: vec![test_webhook(last_notification_sent)],
			last_notification_cooldown_reset: None,
		}
	}

	#[test]
	fn reset_notification_cooldown_is_throttled() {
		let first_reset = lsps_datetime(2_000);
		let mut peer_state = test_peer_state(Some(first_reset));

		assert!(peer_state.reset_notification_cooldown(first_reset));
		assert_eq!(peer_state.webhooks()[0].1.last_notification_sent, None);
		assert_eq!(peer_state.last_notification_cooldown_reset, Some(first_reset));

		let skipped_reset = lsps_datetime_millis(2_000_099);
		let recent_notification = skipped_reset;
		peer_state.webhooks_mut()[0].1.last_notification_sent = Some(recent_notification);

		assert!(!peer_state.reset_notification_cooldown(skipped_reset));
		assert_eq!(peer_state.webhooks()[0].1.last_notification_sent, Some(recent_notification));
		assert_eq!(peer_state.last_notification_cooldown_reset, Some(first_reset));

		let allowed_reset = lsps_datetime_millis(2_000_100);
		assert!(peer_state.reset_notification_cooldown(allowed_reset));
		assert_eq!(peer_state.webhooks()[0].1.last_notification_sent, None);
		assert_eq!(peer_state.last_notification_cooldown_reset, Some(allowed_reset));
	}
}
