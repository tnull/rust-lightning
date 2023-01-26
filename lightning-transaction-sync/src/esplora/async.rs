use crate::error::TxSyncError;
use crate::esplora::{EsploraSyncClient, EsploraClientType};

use lightning::chain::WatchedOutput;
use lightning::chain::{Confirm, Filter};
use lightning::util::logger::Logger;

use bitcoin::{Script, Txid};

use core::ops::Deref;

/// Synchronizes LDK with a given [`Esplora`] server.
///
/// Needs to be registered with a [`ChainMonitor`] via the [`Filter`] interface to be informed of
/// transactions and outputs to monitor for on-chain confirmation, unconfirmation, and
/// reconfirmation.
///
/// [`Esplora`]: https://github.com/Blockstream/electrs
/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
/// [`Filter`]: lightning::chain::Filter
pub struct AsyncEsploraSyncClient<L: Deref>
where
	L::Target: Logger,
{
	inner: EsploraSyncClient<L>,
}

impl<L: Deref> AsyncEsploraSyncClient<L>
where
	L::Target: Logger,
{
	/// Returns a new [`AsyncEsploraSyncClient`] object.
	pub fn new(server_url: String, logger: L) -> Self {
		let inner = EsploraSyncClient::new(server_url, logger);
		Self { inner }
	}

	/// Returns a reference to the underlying esplora client.
	pub fn client(&self) -> &EsploraClientType {
		&self.inner.client()
	}

	/// Returns a new [`AsyncEsploraSyncClient`] object using the given Esplora client.
	pub fn from_client(client: EsploraClientType, logger: L) -> Self {
		Self { inner: EsploraSyncClient::from_client(client, logger) }
	}

	/// Synchronizes the given `confirmables` via their [`Confirm`] interface implementations. This
	/// method should be called regularly to keep LDK up-to-date with current chain data.
	///
	/// For example, instances of [`ChannelManager`] and [`ChainMonitor`] can be informed about the
	/// newest on-chain activity related to the items previously registered via the [`Filter`]
	/// interface.
	///
	/// [`Confirm`]: lightning::chain::Confirm
	/// [`ChainMonitor`]: lightning::chain::chainmonitor::ChainMonitor
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	/// [`Filter`]: lightning::chain::Filter
	pub async fn sync(&self, confirmables: Vec<&(dyn Confirm + Sync + Send)>) -> Result<(), TxSyncError> {
		self.inner.sync(confirmables).await
	}
}

impl<L: Deref> Filter for AsyncEsploraSyncClient<L>
where
	L::Target: Logger,
{
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.inner.register_tx(txid, script_pubkey);
	}

	fn register_output(&self, output: WatchedOutput) {
		self.inner.register_output(output);
	}
}
