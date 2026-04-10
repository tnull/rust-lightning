// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Implementation of the [swap-in-potentiam] protocol.
//!
//! Swap-in-potentiam (SIP) enables mobile wallet users to receive on-chain Bitcoin to a special
//! 2-of-2 address shared with their LSP. Once funds are confirmed at that address, they can be
//! "instantly" moved into a Lightning channel because the LSP already co-owns the UTXO and can
//! trust 0-conf channel funding or splicing from it.
//!
//! [swap-in-potentiam]: https://lists.linuxfoundation.org/pipermail/lightning-dev/2023-January/003810.html

pub mod address;
pub mod event;
pub mod msgs;
