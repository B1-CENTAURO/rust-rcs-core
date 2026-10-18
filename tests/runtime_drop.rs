// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The runtime given to MSRP and SIP can be dropped while they are at work.
//! tokio panics when a runtime is dropped inside one of its tasks, which a
//! task of ours that held the last Arc<Runtime> would do as it ended. The
//! panic is on a worker thread, so a panic hook watches for it; the one test
//! keeps the hook to itself.

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tokio::io::DuplexStream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use rust_rcs_core::msrp::msrp_channel::MsrpChannelManager;
use rust_rcs_core::msrp::msrp_demuxer::MsrpDemuxer;
use rust_rcs_core::sip::sip_core::SipCore;
use rust_rcs_core::sip::sip_subscription::SubscriptionManager;
use rust_rcs_core::sip::sip_transaction::SipTransactionManager;
use rust_rcs_core::sip::sip_transport::TransportMessage;

const LOCAL: &[u8] = b"msrp://127.0.0.1:2855/local;tcp";
const REMOTE: &[u8] = b"msrp://127.0.0.1:2856/remote;tcp";

static DROPPED_IN_A_TASK: AtomicBool = AtomicBool::new(false);

#[test]
fn the_runtime_can_be_dropped_while_msrp_and_sip_are_at_work() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.to_string().contains("Cannot drop a runtime") {
            DROPPED_IN_A_TASK.store(true, Ordering::SeqCst);
        }
        hook(info);
    }));

    // a message waiting to queue its next chunk, which ends once nothing takes
    // its chunks any more
    let rt = Arc::new(Runtime::new().unwrap());
    let demuxer = MsrpDemuxer::new(LOCAL.to_vec(), REMOTE.to_vec());
    let (tx, mut rx) = mpsc::channel(1);
    demuxer.start(
        LOCAL.to_vec(),
        REMOTE.to_vec(),
        Some(b"text/plain".to_vec()),
        50 * 1024,
        Cursor::new(vec![b'x'; 50 * 1024]),
        |_, _| {},
        tx,
        &rt,
    );
    rt.block_on(rx.recv()).unwrap();
    drop(rt);
    drop(rx);

    // the manager's loop, which ends once the manager and its senders are gone
    let rt = Arc::new(Runtime::new().unwrap());
    let (tx, rx) = mpsc::channel(8);
    let manager = MsrpChannelManager::new(
        rx,
        |_: &[u8], _: &[u8]| -> DuplexStream { panic!("nothing to connect") },
        Arc::clone(&rt),
    );
    drop(rt);
    drop(manager);
    drop(tx);

    // the loops of SIP's transaction manager and core, which end on Exit
    let rt = Arc::new(Runtime::new().unwrap());
    let (tm, tm_events) = SipTransactionManager::new(&rt);
    let tm = Arc::new(tm);
    let sm = Arc::new(SubscriptionManager::new(500));
    let core = SipCore::new(&sm, &tm, tm_events, Vec::new(), Vec::new(), &rt);
    let ctrl = tm.get_ctrl_itf();
    drop(rt);
    drop(core);
    drop(sm);
    drop(tm);
    ctrl.blocking_send(TransportMessage::Exit).unwrap();

    thread::sleep(Duration::from_secs(1));
    assert!(
        !DROPPED_IN_A_TASK.load(Ordering::SeqCst),
        "a task dropped the runtime"
    );
}
