// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Per-peer state containers shared by the LSPS protocol handlers.

use crate::persist::LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE;
use crate::prelude::hash_map::Entry;
use crate::prelude::{new_hash_map, HashMap};
use crate::sync::{Mutex, RwLock};

use lightning::io::Cursor;
use lightning::util::persist::KVStore;
use lightning::util::ser::{Readable, Writeable};

use bitcoin::secp256k1::PublicKey;

use alloc::string::ToString;
use alloc::vec::Vec;

use core::ops::{Deref, DerefMut};
use core::str::FromStr;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The maximum number of peers a service handler keeps state for.
pub(crate) const MAX_TOTAL_PEERS: usize = 100000;

/// Per-peer state of a service handler that is kept in a [`PersistedPeerStates`].
pub(crate) trait PrunablePeerState {
	/// Context the handler provides for a single pruning pass.
	type PruneContext;

	/// Drops any expired state, returning whether persisted state was changed.
	///
	/// The context is mutable so that pruning can hand back anything the handler needs to act on
	/// after all locks have been released.
	fn prune_expired(
		&mut self, counterparty_node_id: &PublicKey, ctx: &mut Self::PruneContext,
	) -> bool;

	/// Returns whether the state holds nothing worth keeping, i.e., whether it may be dropped from
	/// memory and removed from the store.
	fn is_prunable(&self, counterparty_node_id: &PublicKey, ctx: &Self::PruneContext) -> bool;
}

/// A peer's state alongside a flag tracking whether it needs to be persisted.
///
/// Mutable access to the state does not set the flag, as not all state is persisted. Callers
/// modifying persisted state must set `needs_persist` themselves.
pub(crate) struct PeerStateEntry<S> {
	pub(crate) needs_persist: bool,
	state: S,
}

impl<S> PeerStateEntry<S> {
	pub(crate) fn new(state: S) -> Self {
		Self { needs_persist: false, state }
	}
}

impl<S> Deref for PeerStateEntry<S> {
	type Target = S;

	fn deref(&self) -> &S {
		&self.state
	}
}

impl<S> DerefMut for PeerStateEntry<S> {
	fn deref_mut(&mut self) -> &mut S {
		&mut self.state
	}
}

pub(crate) type PeerStateMap<S> = HashMap<PublicKey, Mutex<PeerStateEntry<S>>>;

/// Returned when inserting a new peer would exceed [`MAX_TOTAL_PEERS`].
pub(crate) struct TooManyPeers;

/// Returns the state of the given peer, inserting a default one unless the number of tracked peers
/// already reached [`MAX_TOTAL_PEERS`]. Peers that are already tracked are never rejected.
pub(crate) fn get_or_insert_peer_state<'a, S: Default>(
	per_peer_state: &'a mut PeerStateMap<S>, counterparty_node_id: &PublicKey,
) -> Result<&'a mut Mutex<PeerStateEntry<S>>, TooManyPeers> {
	let num_peers = per_peer_state.len();
	match per_peer_state.entry(*counterparty_node_id) {
		Entry::Occupied(e) => Ok(e.into_mut()),
		Entry::Vacant(e) => {
			if num_peers >= MAX_TOTAL_PEERS {
				return Err(TooManyPeers);
			}
			Ok(e.insert(Mutex::new(PeerStateEntry::new(S::default()))))
		},
	}
}

/// Per-peer state that is persisted to a [`KVStore`], one key per peer.
///
/// Dereferences to the map of peer states. Entries must only be removed by [`Self::persist`], which
/// also removes them from the store.
pub(crate) struct PersistedPeerStates<S, K: KVStore + Clone> {
	per_peer_state: RwLock<PeerStateMap<S>>,
	kv_store: K,
	secondary_namespace: &'static str,
	persistence_in_flight: AtomicUsize,
}

impl<S, K: KVStore + Clone> Deref for PersistedPeerStates<S, K> {
	type Target = RwLock<PeerStateMap<S>>;

	fn deref(&self) -> &Self::Target {
		&self.per_peer_state
	}
}

impl<S: PrunablePeerState + Readable + Writeable, K: KVStore + Clone> PersistedPeerStates<S, K> {
	/// Reads all peer states persisted under the given secondary namespace.
	pub(crate) async fn load(
		kv_store: K, secondary_namespace: &'static str,
	) -> Result<Self, lightning::io::Error> {
		let mut per_peer_state = new_hash_map();

		for stored_key in kv_store
			.list(LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, secondary_namespace)
			.await?
		{
			let mut reader = Cursor::new(
				kv_store
					.read(
						LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
						secondary_namespace,
						&stored_key,
					)
					.await?,
			);

			let peer_state = S::read(&mut reader).map_err(|_| {
				lightning::io::Error::new(
					lightning::io::ErrorKind::InvalidData,
					"Failed to deserialize peer state",
				)
			})?;

			let key = PublicKey::from_str(&stored_key).map_err(|_| {
				lightning::io::Error::new(
					lightning::io::ErrorKind::InvalidData,
					"Failed to deserialize stored key entry",
				)
			})?;

			per_peer_state.insert(key, Mutex::new(PeerStateEntry::new(peer_state)));
		}

		Ok(Self {
			per_peer_state: RwLock::new(per_peer_state),
			kv_store,
			secondary_namespace,
			persistence_in_flight: AtomicUsize::new(0),
		})
	}

	/// Prunes expired state of all peers, but leaves removing emptied peers to [`Self::persist`].
	pub(crate) fn prune_expired_all(&self, ctx: &mut S::PruneContext) {
		let outer_state_lock = self.per_peer_state.read().unwrap();
		for (counterparty_node_id, inner_state_lock) in outer_state_lock.iter() {
			let mut peer_state_lock = inner_state_lock.lock().unwrap();
			if peer_state_lock.prune_expired(counterparty_node_id, ctx) {
				peer_state_lock.needs_persist = true;
			}
		}
	}

	/// Prunes expired state, persists all peers that need persisting, and removes prunable peers
	/// from memory and the store.
	///
	/// Returns whether any data was written to or removed from the store.
	pub(crate) async fn persist(
		&self, ctx: &mut S::PruneContext,
	) -> Result<bool, lightning::io::Error> {
		// TODO: We should eventually persist in parallel, however, when we do, we probably want to
		// introduce some batching to upper-bound the number of requests inflight at any given
		// time.

		if self.persistence_in_flight.fetch_add(1, Ordering::AcqRel) > 0 {
			// If we're not the first event processor to get here, just return early, the increment
			// we just did will be treated as "go around again" at the end.
			return Ok(false);
		}

		let mut did_persist = false;

		loop {
			match self.do_persist(ctx).await {
				Ok(pass_did_persist) => did_persist |= pass_did_persist,
				Err(e) => {
					self.persistence_in_flight.store(0, Ordering::Release);
					return Err(e);
				},
			}

			if self.persistence_in_flight.fetch_sub(1, Ordering::AcqRel) != 1 {
				// If another thread incremented the state while we were running we should go
				// around again, but only once.
				self.persistence_in_flight.store(1, Ordering::Release);
				continue;
			}
			break;
		}

		Ok(did_persist)
	}

	async fn do_persist(&self, ctx: &mut S::PruneContext) -> Result<bool, lightning::io::Error> {
		let mut did_persist = false;
		let mut need_remove = Vec::new();
		let mut need_persist = Vec::new();

		self.prune_expired_all(ctx);
		{
			// First build a list of peers to persist and prune with the read lock. This allows
			// us to avoid the write lock unless we actually need to remove a node.
			let outer_state_lock = self.per_peer_state.read().unwrap();
			for (counterparty_node_id, inner_state_lock) in outer_state_lock.iter() {
				let peer_state_lock = inner_state_lock.lock().unwrap();
				if peer_state_lock.is_prunable(counterparty_node_id, ctx) {
					need_remove.push(*counterparty_node_id);
				} else if peer_state_lock.needs_persist {
					need_persist.push(*counterparty_node_id);
				}
			}
		}

		for counterparty_node_id in need_persist.into_iter() {
			debug_assert!(!need_remove.contains(&counterparty_node_id));
			self.persist_peer_state(counterparty_node_id).await?;
			did_persist = true;
		}

		for counterparty_node_id in need_remove {
			// Persist the emptied state before removing the key so that if the removal
			// below fails, the on-disk record matches the in-memory state. Otherwise a
			// restart would reload the peer with state that was already dropped.
			self.persist_peer_state(counterparty_node_id).await?;

			let mut future_opt = None;
			let mut removed_state = None;
			{
				// We need to take the `per_peer_state` write lock to remove an entry, but also
				// have to hold it until after the `remove` call returns (but not through
				// future completion) to ensure that writes for the peer's state are
				// well-ordered with other `persist_peer_state` calls even across the removal
				// itself.
				let mut per_peer_state = self.per_peer_state.write().unwrap();
				if let Entry::Occupied(mut entry) = per_peer_state.entry(counterparty_node_id) {
					let state = entry.get_mut().get_mut().unwrap();
					if state.is_prunable(&counterparty_node_id, ctx) {
						removed_state = Some(entry.remove());
						let key = counterparty_node_id.to_string();
						future_opt = Some(self.kv_store.remove(
							LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
							self.secondary_namespace,
							&key,
							true,
						));
					} else {
						// If the peer got new state, force a re-persist of the current state.
						state.needs_persist = true;
					}
				} else {
					// This should never happen, we can only have one `persist` call
					// in-progress at once and map entries are only removed by it.
					debug_assert!(false);
				}
			}
			if let Some(future) = future_opt {
				if let Err(e) = future.await {
					// Put the emptied state back so a later `persist` retries the removal,
					// unless the peer was re-added in the meantime.
					if let Some(mut state) = removed_state {
						state.get_mut().unwrap().needs_persist = true;
						self.per_peer_state
							.write()
							.unwrap()
							.entry(counterparty_node_id)
							.or_insert(state);
					}
					return Err(e);
				}
				did_persist = true;
			} else {
				self.persist_peer_state(counterparty_node_id).await?;
				did_persist = true;
			}
		}

		Ok(did_persist)
	}

	/// Persists the given peer's state if it needs persisting.
	pub(crate) async fn persist_peer_state(
		&self, counterparty_node_id: PublicKey,
	) -> Result<(), lightning::io::Error> {
		let fut = {
			let outer_state_lock = self.per_peer_state.read().unwrap();
			match outer_state_lock.get(&counterparty_node_id) {
				None => {
					// We dropped the peer state by now.
					return Ok(());
				},
				Some(entry) => {
					let mut peer_state_lock = entry.lock().unwrap();
					if !peer_state_lock.needs_persist {
						// We already have persisted otherwise by now.
						return Ok(());
					} else {
						peer_state_lock.needs_persist = false;
						let key = counterparty_node_id.to_string();
						let encoded = peer_state_lock.state.encode();
						// Begin the write with the entry lock held. This avoids racing with
						// potentially-in-flight `persist` calls writing state for the same peer.
						self.kv_store.write(
							LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
							self.secondary_namespace,
							&key,
							encoded,
						)
					}
				},
			}
		};

		fut.await.map_err(|e| {
			self.per_peer_state
				.read()
				.unwrap()
				.get(&counterparty_node_id)
				.map(|p| p.lock().unwrap().needs_persist = true);
			e
		})
	}
}

/// Per-peer state that is only kept in memory.
///
/// Dereferences to the map of peer states.
pub(crate) struct PeerStates<S> {
	per_peer_state: RwLock<HashMap<PublicKey, Mutex<S>>>,
}

impl<S> PeerStates<S> {
	pub(crate) fn new() -> Self {
		Self { per_peer_state: RwLock::new(new_hash_map()) }
	}

	/// Drops the given peer's state if `is_empty` returns `true` for it.
	pub(crate) fn remove_if(
		&self, counterparty_node_id: &PublicKey, is_empty: impl FnOnce(&S) -> bool,
	) {
		let mut outer_state_lock = self.per_peer_state.write().unwrap();
		if let Entry::Occupied(mut entry) = outer_state_lock.entry(*counterparty_node_id) {
			if is_empty(entry.get_mut().get_mut().unwrap()) {
				entry.remove();
			}
		}
	}
}

impl<S> Deref for PeerStates<S> {
	type Target = RwLock<HashMap<PublicKey, Mutex<S>>>;

	fn deref(&self) -> &Self::Target {
		&self.per_peer_state
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::tests::utils::parse_pubkey;
	use crate::utils::async_poll::dummy_waker;

	use lightning::impl_ser_tlv_based;
	use lightning::util::persist::{KVStoreSync, KVStoreSyncWrapper};
	use lightning::util::test_utils::TestStore;

	use alloc::string::String;
	use core::future::Future;
	use core::pin::pin;
	use core::task;
	use std::sync::Arc;

	const NAMESPACE: &str = "test_peer_state";

	// A peer state with one persisted and one transient value. The persisted value expires once
	// the prune context, a timestamp, reaches it.
	#[derive(Default)]
	struct TestPeerState {
		expires_at: u64,
		pending_requests: u64,
	}

	impl_ser_tlv_based!(TestPeerState, {
		(0, expires_at, required),
		(_unused, pending_requests, (static_value, 0)),
	});

	impl PrunablePeerState for TestPeerState {
		type PruneContext = u64;

		fn prune_expired(&mut self, _: &PublicKey, now: &mut u64) -> bool {
			if self.expires_at != 0 && self.expires_at <= *now {
				self.expires_at = 0;
				return true;
			}
			false
		}

		fn is_prunable(&self, _: &PublicKey, _: &u64) -> bool {
			self.expires_at == 0 && self.pending_requests == 0
		}
	}

	struct FailableStore {
		inner: TestStore,
		fail_writes: Mutex<bool>,
		fail_removes: Mutex<bool>,
	}

	impl FailableStore {
		fn new() -> Self {
			Self {
				inner: TestStore::new(false),
				fail_writes: Mutex::new(false),
				fail_removes: Mutex::new(false),
			}
		}

		fn error() -> lightning::io::Error {
			lightning::io::Error::new(lightning::io::ErrorKind::Other, "store unavailable")
		}
	}

	impl KVStoreSync for FailableStore {
		fn read(
			&self, primary: &str, secondary: &str, key: &str,
		) -> Result<Vec<u8>, lightning::io::Error> {
			KVStoreSync::read(&self.inner, primary, secondary, key)
		}

		fn write(
			&self, primary: &str, secondary: &str, key: &str, buf: Vec<u8>,
		) -> Result<(), lightning::io::Error> {
			if *self.fail_writes.lock().unwrap() {
				return Err(Self::error());
			}
			KVStoreSync::write(&self.inner, primary, secondary, key, buf)
		}

		fn remove(
			&self, primary: &str, secondary: &str, key: &str, lazy: bool,
		) -> Result<(), lightning::io::Error> {
			if *self.fail_removes.lock().unwrap() {
				return Err(Self::error());
			}
			KVStoreSync::remove(&self.inner, primary, secondary, key, lazy)
		}

		fn list(
			&self, primary: &str, secondary: &str,
		) -> Result<Vec<String>, lightning::io::Error> {
			KVStoreSync::list(&self.inner, primary, secondary)
		}
	}

	type TestStates = PersistedPeerStates<TestPeerState, KVStoreSyncWrapper<Arc<FailableStore>>>;

	fn poll_ready<F: Future>(fut: F) -> F::Output {
		let waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&waker);
		match pin!(fut).poll(&mut ctx) {
			task::Poll::Ready(res) => res,
			task::Poll::Pending => panic!("future was expected to be ready"),
		}
	}

	fn load(store: &Arc<FailableStore>) -> TestStates {
		poll_ready(PersistedPeerStates::load(KVStoreSyncWrapper(Arc::clone(store)), NAMESPACE))
			.unwrap()
	}

	fn stored_keys(store: &FailableStore) -> Vec<String> {
		KVStoreSync::list(store, LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, NAMESPACE)
			.unwrap()
	}

	fn peer() -> PublicKey {
		parse_pubkey("02c0ded160a4a70d71058509b647949a938924d3a6e109c6eb6aee8e2bb27dc79c").unwrap()
	}

	fn insert_peer(
		states: &TestStates, expires_at: u64, pending_requests: u64, needs_persist: bool,
	) {
		let mut outer_state_lock = states.write().unwrap();
		let inner_state_lock =
			get_or_insert_peer_state(&mut outer_state_lock, &peer()).ok().unwrap();
		let mut peer_state_lock = inner_state_lock.lock().unwrap();
		peer_state_lock.expires_at = expires_at;
		peer_state_lock.pending_requests = pending_requests;
		peer_state_lock.needs_persist = needs_persist;
	}

	fn needs_persist(states: &TestStates) -> Option<bool> {
		states.read().unwrap().get(&peer()).map(|p| p.lock().unwrap().needs_persist)
	}

	#[test]
	fn persists_dirty_state_and_reloads_it() {
		let store = Arc::new(FailableStore::new());
		let states = load(&store);
		insert_peer(&states, 5, 1, true);

		assert!(poll_ready(states.persist(&mut 0)).unwrap());
		assert_eq!(needs_persist(&states), Some(false));
		assert!(!poll_ready(states.persist(&mut 0)).unwrap());

		let reloaded = load(&store);
		let outer_state_lock = reloaded.read().unwrap();
		let peer_state_lock = outer_state_lock.get(&peer()).unwrap().lock().unwrap();
		assert_eq!(peer_state_lock.expires_at, 5);
		assert_eq!(peer_state_lock.pending_requests, 0);
		assert!(!peer_state_lock.needs_persist);
	}

	#[test]
	fn does_not_persist_clean_state() {
		let store = Arc::new(FailableStore::new());
		let states = load(&store);
		insert_peer(&states, 0, 1, false);

		assert!(!poll_ready(states.persist(&mut 0)).unwrap());
		assert!(stored_keys(&store).is_empty());
		assert_eq!(needs_persist(&states), Some(false));
	}

	#[test]
	fn removes_pruned_peer_from_memory_and_store() {
		let store = Arc::new(FailableStore::new());
		let states = load(&store);
		insert_peer(&states, 5, 0, true);
		assert!(poll_ready(states.persist(&mut 0)).unwrap());
		assert_eq!(stored_keys(&store).len(), 1);

		assert!(poll_ready(states.persist(&mut 5)).unwrap());
		assert!(states.read().unwrap().is_empty());
		assert!(stored_keys(&store).is_empty());
	}

	#[test]
	fn keeps_peer_with_transient_state_after_pruning() {
		let store = Arc::new(FailableStore::new());
		let states = load(&store);
		insert_peer(&states, 5, 1, true);
		assert!(poll_ready(states.persist(&mut 0)).unwrap());

		assert!(poll_ready(states.persist(&mut 5)).unwrap());
		assert_eq!(needs_persist(&states), Some(false));
		assert_eq!(
			load(&store).read().unwrap().get(&peer()).unwrap().lock().unwrap().expires_at,
			0
		);
	}

	#[test]
	fn retries_failed_write() {
		let store = Arc::new(FailableStore::new());
		let states = load(&store);
		insert_peer(&states, 5, 0, true);

		*store.fail_writes.lock().unwrap() = true;
		assert!(poll_ready(states.persist(&mut 0)).is_err());
		assert_eq!(needs_persist(&states), Some(true));
		assert!(stored_keys(&store).is_empty());

		*store.fail_writes.lock().unwrap() = false;
		assert!(poll_ready(states.persist(&mut 0)).unwrap());
		assert_eq!(stored_keys(&store).len(), 1);
	}

	#[test]
	fn reinserts_peer_and_persists_emptied_state_if_removal_fails() {
		let store = Arc::new(FailableStore::new());
		let states = load(&store);
		insert_peer(&states, 5, 0, true);
		assert!(poll_ready(states.persist(&mut 0)).unwrap());

		*store.fail_removes.lock().unwrap() = true;
		assert!(poll_ready(states.persist(&mut 5)).is_err());
		assert_eq!(needs_persist(&states), Some(true));
		// The emptied state was written before the failed removal, so a restart wouldn't resurrect
		// the pruned state.
		assert_eq!(
			load(&store).read().unwrap().get(&peer()).unwrap().lock().unwrap().expires_at,
			0
		);

		*store.fail_removes.lock().unwrap() = false;
		assert!(poll_ready(states.persist(&mut 5)).unwrap());
		assert!(states.read().unwrap().is_empty());
		assert!(stored_keys(&store).is_empty());
	}

	#[test]
	fn concurrent_persist_goes_around_again() {
		// `TestStore`'s async writes stay pending until completed explicitly.
		let store = Arc::new(TestStore::new(false));
		let states = poll_ready(PersistedPeerStates::<TestPeerState, _>::load(
			Arc::clone(&store),
			NAMESPACE,
		))
		.unwrap();
		let other_peer =
			parse_pubkey("027100442c3b79f606f80f322d98d499eefcb060599efc5d4ecb00209c2cb54190")
				.unwrap();
		{
			let mut outer_state_lock = states.write().unwrap();
			let mut peer_state_lock = get_or_insert_peer_state(&mut outer_state_lock, &peer())
				.ok()
				.unwrap()
				.lock()
				.unwrap();
			peer_state_lock.expires_at = 5;
			peer_state_lock.needs_persist = true;
		}

		let waker = dummy_waker();
		let mut ctx = task::Context::from_waker(&waker);
		let mut now = 0;
		let mut first = Box::pin(states.persist(&mut now));
		assert!(first.as_mut().poll(&mut ctx).is_pending());

		// A concurrent call returns immediately, but marks that another pass is needed.
		{
			let mut outer_state_lock = states.write().unwrap();
			let mut peer_state_lock = get_or_insert_peer_state(&mut outer_state_lock, &other_peer)
				.ok()
				.unwrap()
				.lock()
				.unwrap();
			peer_state_lock.expires_at = 5;
			peer_state_lock.needs_persist = true;
		}
		assert!(!poll_ready(states.persist(&mut 0)).unwrap());

		// The first call picks up the other peer in its second pass.
		let res = loop {
			store.complete_all_async_writes();
			if let task::Poll::Ready(res) = first.as_mut().poll(&mut ctx) {
				break res;
			}
		};
		assert!(res.unwrap());
		let keys =
			KVStoreSync::list(&*store, LIQUIDITY_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, NAMESPACE)
				.unwrap();
		assert_eq!(keys.len(), 2);
	}

	#[test]
	fn remove_if_only_drops_matching_state() {
		let states = PeerStates::<Vec<u8>>::new();
		states.write().unwrap().insert(peer(), Mutex::new(vec![1]));

		states.remove_if(&peer(), |s| s.is_empty());
		assert!(states.read().unwrap().contains_key(&peer()));

		states.read().unwrap().get(&peer()).unwrap().lock().unwrap().clear();
		states.remove_if(&peer(), |s| s.is_empty());
		assert!(!states.read().unwrap().contains_key(&peer()));
	}
}
