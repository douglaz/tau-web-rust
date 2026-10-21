//! The single-threaded writer boundary for a stoppable unresolved-command wait.

use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

pub(super) async fn until<T>(
    stopped: impl Future<Output = ()>,
    work: impl Future<Output = T>,
) -> Option<T> {
    let mut stopped = pin!(stopped);
    let mut work = pin!(work);
    poll_fn(|cx| {
        if stopped.as_mut().poll(cx).is_ready() {
            Poll::Ready(None)
        } else {
            work.as_mut().poll(cx).map(Some)
        }
    })
    .await
}

pub(crate) async fn unless_stopped<L: Future, T>(
    lock: L,
    stopped: impl Future<Output = ()>,
    is_stopped: impl Fn() -> bool,
    commit: impl AsyncFnOnce(L::Output) -> T,
) -> Option<T> {
    let guard = until(stopped, lock).await?;
    // No await between this check under the writer and starting the commit. Stopping cannot
    // interleave here in the worker; once begun, the commit must never be cancelled by a stop.
    if is_stopped() {
        return None;
    }
    Some(commit(guard).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::task::{Context, Waker};

    async fn signal(value: &Cell<bool>) {
        poll_fn(|_| {
            if value.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    #[test]
    fn stop_after_read_answers_without_writer_and_appends_nothing() {
        let writer_free = Cell::new(false);
        let stopped = Cell::new(false);
        let appended = Cell::new(false);
        let request = async {
            // The read has completed; only its evidence append needs the writer.
            let record = "finished record as read";
            let journaled = unless_stopped(
                signal(&writer_free),
                signal(&stopped),
                || stopped.get(),
                async |()| {
                    appended.set(true);
                },
            )
            .await;
            (record, journaled)
        };
        let mut request = pin!(request);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(request.as_mut().poll(&mut cx).is_pending());
        stopped.set(true);
        assert_eq!(
            request.as_mut().poll(&mut cx),
            Poll::Ready(("finished record as read", None)),
            "criterion 8: stopped evidence wait answers with its read without waiting for the writer"
        );
        assert!(!writer_free.get());
        assert!(
            !appended.get(),
            "criterion 8: stop begins no evidence append and settles nothing"
        );
        writer_free.set(true);
        assert!(
            !appended.get(),
            "criterion 8: freeing the writer after stop appends nothing"
        );
    }

    #[test]
    fn stop_is_rechecked_under_writer_before_commit() {
        let stopped = Cell::new(false);
        let appended = Cell::new(false);
        let request = unless_stopped(
            async {
                stopped.set(true);
            },
            signal(&stopped),
            || stopped.get(),
            async |()| {
                appended.set(true);
            },
        );
        let mut request = pin!(request);
        assert_eq!(
            request
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(None)
        );
        assert!(
            !appended.get(),
            "criterion 8: stop is checked after writer acquisition"
        );
    }

    #[test]
    fn stop_during_commit_allows_whole_append() {
        let stopped = Cell::new(false);
        let finish = Cell::new(false);
        let begun = Cell::new(false);
        let appended = Cell::new(false);
        let request = unless_stopped(
            async {},
            signal(&stopped),
            || stopped.get(),
            async |()| {
                begun.set(true);
                signal(&finish).await;
                appended.set(true);
                "journaled evidence"
            },
        );
        let mut request = pin!(request);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(request.as_mut().poll(&mut cx).is_pending());
        assert!(begun.get());
        stopped.set(true);
        assert!(
            request.as_mut().poll(&mut cx).is_pending(),
            "criterion 8: stop never drops a begun commit"
        );
        finish.set(true);
        assert_eq!(
            request.as_mut().poll(&mut cx),
            Poll::Ready(Some("journaled evidence"))
        );
        assert!(appended.get());
    }
}
