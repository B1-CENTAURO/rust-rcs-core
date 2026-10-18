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

use std::ops::Deref;
use std::sync::Arc;

use tokio::runtime::{Handle, Runtime};

/// An `Arc<Runtime>` for a task, or for something a task may drop, to hold.
///
/// tokio panics when a runtime is dropped inside one of its tasks, which the
/// last `Arc<Runtime>` would be when the task holding it ends. The last
/// `HeldRuntime` shuts the runtime down in the background there instead, as
/// tokio allows; elsewhere it drops the runtime as usual.
pub(crate) struct HeldRuntime(Option<Arc<Runtime>>);

impl HeldRuntime {
    pub(crate) fn new(rt: &Arc<Runtime>) -> HeldRuntime {
        HeldRuntime(Some(Arc::clone(rt)))
    }
}

impl From<Arc<Runtime>> for HeldRuntime {
    fn from(rt: Arc<Runtime>) -> HeldRuntime {
        HeldRuntime(Some(rt))
    }
}

impl Deref for HeldRuntime {
    type Target = Arc<Runtime>;

    fn deref(&self) -> &Arc<Runtime> {
        self.0.as_ref().unwrap() // taken only when dropped
    }
}

impl Drop for HeldRuntime {
    fn drop(&mut self) {
        // into_inner() gives the runtime to exactly one of the last holders,
        // so that no other drops it as it drops its Arc
        if let Some(rt) = self.0.take().and_then(Arc::into_inner) {
            if Handle::try_current().is_ok() {
                rt.shutdown_background();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::runtime::Runtime;
    use tokio::sync::oneshot;

    use super::HeldRuntime;

    #[test]
    fn the_last_one_shuts_the_runtime_down_inside_a_task() {
        let rt = Arc::new(Runtime::new().unwrap());

        // a task that runs until the runtime is shut down
        let (pending_tx, pending_rx) = mpsc::channel::<()>();
        rt.spawn(async move {
            let _pending_tx = pending_tx;
            std::future::pending::<()>().await;
        });

        // a task that ends holding the last HeldRuntime
        let held = HeldRuntime::new(&rt);
        let (go_tx, go_rx) = oneshot::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        rt.spawn(async move {
            let _ = go_rx.await;
            drop(held);
            let _ = done_tx.send(());
        });

        drop(rt);
        go_tx.send(()).unwrap();

        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the task did not get past dropping the runtime");
        assert_eq!(
            pending_rx.recv_timeout(Duration::from_secs(10)),
            Err(RecvTimeoutError::Disconnected),
            "the runtime is shut down"
        );
    }
}
