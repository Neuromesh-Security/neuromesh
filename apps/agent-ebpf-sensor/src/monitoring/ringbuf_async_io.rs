//! Tokio `AsyncFd::async_io(_mut)` readiness contract for aya `RingBuf` drains.
//!
//! ## Why this exists
//!
//! aya 0.14.0 does **not** wrap Tokio. `RingBuf` only exposes [`AsRawFd`] /
//! [`AsFd`] and documents that callers build `tokio::io::unix::AsyncFd` themselves.
//! aya's own example always calls `guard.clear_ready()` after draining
//! (`aya/src/maps/ring_buf.rs`, docs example loop).
//!
//! Tokio 1.52 `Registration::async_io` (used by `AsyncFd::async_io_mut`) only
//! clears readiness when the closure returns `ErrorKind::WouldBlock`:
//!
//! ```ignore
//! // tokio/src/runtime/io/registration.rs
//! match f() {
//!     Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
//!         self.clear_readiness(event);
//!     }
//!     x => return x,
//! }
//! ```
//!
//! Returning `Ok(())` after an **empty** `RingBuf::next()` leave keeps the fd
//! marked ready → the next `select!` iteration re-enters immediately → busy-spin
//! (~93–97% idle CPU on 1 vCPU). See Issue #103.
//!
//! ## Contract we enforce
//!
//! - ≥1 item drained → `Ok(())` (more data may still be pending; re-enter is OK)
//! - 0 items drained → `WouldBlock` (clear readiness; wait for a new edge)

use std::io;

/// Map a completed aya `RingBuf` drain attempt to the `AsyncFd::async_io(_mut)`
/// result Tokio expects.
#[inline]
pub fn ringbuf_drain_outcome(drained_any: bool) -> io::Result<()> {
    if drained_any {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn empty_drain_returns_would_block() {
        let err = ringbuf_drain_outcome(false).expect_err("empty must WouldBlock");
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    }

    #[test]
    fn non_empty_drain_returns_ok() {
        ringbuf_drain_outcome(true).expect("drained items must Ok");
    }

    /// Prove the WouldBlock-on-empty contract does not drop a subsequent real
    /// event: after an empty readiness observation we still deliver the next
    /// write within a short timeout (Unix `AsyncFd` + non-blocking stream).
    #[cfg(unix)]
    #[tokio::test]
    async fn would_block_on_empty_still_delivers_next_event() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream as StdUnixStream;
        use tokio::io::unix::AsyncFd;
        use tokio::io::Interest;

        let (std_reader, mut std_writer) = StdUnixStream::pair().expect("unixstream pair");
        std_reader
            .set_nonblocking(true)
            .expect("reader nonblocking");
        std_writer
            .set_nonblocking(true)
            .expect("writer nonblocking");
        // Wrap the *std* fd — Tokio UnixStream is already reactor-registered and
        // cannot be nested under AsyncFd (EEXIST / AlreadyExists).
        let mut async_fd =
            AsyncFd::with_interest(std_reader, Interest::READABLE).expect("AsyncFd::with_interest");

        let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let received_task = Arc::clone(&received);
        let consumer = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            for _ in 0..8 {
                let outcome = async_fd
                    .async_io_mut(Interest::READABLE, |stream| {
                        let mut drained_any = false;
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    drained_any = true;
                                    received_task.lock().unwrap().extend_from_slice(&buf[..n]);
                                }
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) => return Err(e),
                            }
                        }
                        ringbuf_drain_outcome(drained_any)
                    })
                    .await;
                if let Err(e) = outcome {
                    panic!("unexpected async_io error: {e}");
                }
                if !received_task.lock().unwrap().is_empty() {
                    break;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        std_writer
            .write_all(b"event-1")
            .expect("write event payload");
        std_writer.flush().expect("flush");

        tokio::time::timeout(Duration::from_secs(2), consumer)
            .await
            .expect("consumer timed out — event delivery broken by WouldBlock contract")
            .expect("consumer join");

        let got = received.lock().unwrap().clone();
        assert_eq!(
            got, b"event-1",
            "payload must be received intact after empty-drain WouldBlock path"
        );
    }

    /// Idle empty drain must not complete `async_io_mut` with Ok in a tight
    /// spin: with no writer activity the future stays pending (readiness cleared).
    #[cfg(unix)]
    #[tokio::test]
    async fn empty_drain_does_not_busy_complete_ok() {
        use std::io::Read;
        use std::os::unix::net::UnixStream as StdUnixStream;
        use tokio::io::unix::AsyncFd;
        use tokio::io::Interest;

        let (std_reader, _std_writer) = StdUnixStream::pair().expect("unixstream pair");
        std_reader
            .set_nonblocking(true)
            .expect("reader nonblocking");
        let mut async_fd =
            AsyncFd::with_interest(std_reader, Interest::READABLE).expect("AsyncFd::with_interest");

        let mut buf = [0u8; 8];
        let poll_once = async_fd.async_io_mut(Interest::READABLE, |stream| {
            let mut drained_any = false;
            match stream.read(&mut buf) {
                Ok(0) => {}
                Ok(_) => drained_any = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
            ringbuf_drain_outcome(drained_any)
        });

        let timed_out = tokio::time::timeout(Duration::from_millis(75), poll_once)
            .await
            .is_err();
        assert!(
            timed_out,
            "empty drain must leave async_io pending (WouldBlock cleared readiness), not Ok-spin"
        );
    }
}
