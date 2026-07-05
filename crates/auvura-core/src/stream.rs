//! Streaming redaction API for real-time text pipelines.
//!
//! Provides [`StreamingRedactor`] which wraps a [`Redactor`] and applies
//! PII redaction to a [`Stream`] of text chunks. Handles chunk boundaries
//! by buffering text and flushing at safe boundaries (whitespace).
//!
//! # Example
//!
//! ```rust
//! use auvura_core::redactor::Redactor;
//! use auvura_core::stream::StreamingRedactor;
//! use futures::stream;
//! use futures::StreamExt;
//!
//! # async fn example() {
//! let redactor = Redactor::new(vec![], Default::default());
//! let streaming = StreamingRedactor::new(redactor);
//!
//! let chunks = vec![
//!     Ok::<_, std::io::Error>("Contact ".to_string()),
//!     Ok("john@example.com ".to_string()),
//!     Ok("for help".to_string()),
//! ];
//! let input = stream::iter(chunks);
//!
//! let result: Vec<_> = streaming.redact_stream(input)
//!     .collect()
//!     .await;
//! # }
//! ```

use crate::redactor::Redactor;
use futures_core::Stream;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Wraps a [`Redactor`] to provide streaming redaction over [`Stream`]s.
///
/// Buffers incoming text chunks and redacts at safe boundaries (whitespace).
/// Partial text at chunk boundaries is held in the buffer until more data
/// arrives or the stream ends.
pub struct StreamingRedactor {
    redactor: Redactor,
}

impl StreamingRedactor {
    /// Create a new `StreamingRedactor` wrapping the given `Redactor`.
    pub fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }

    /// Get a reference to the inner `Redactor`.
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// Consume this `StreamingRedactor` and return the inner `Redactor`.
    pub fn into_inner(self) -> Redactor {
        self.redactor
    }

    /// Wrap an input stream, redacting PII from each accumulated chunk.
    ///
    /// The output stream yields redacted text chunks. Text is buffered
    /// internally and flushed when a safe boundary (whitespace) is found,
    /// or when the input stream ends.
    pub fn redact_stream<S, E>(self, stream: S) -> RedactStream<S>
    where
        S: Stream<Item = Result<String, E>>,
    {
        RedactStream {
            inner: stream,
            redactor: self.redactor,
            buffer: String::new(),
            done: false,
        }
    }
}

/// Convenience extension trait for [`Redactor`].
pub trait RedactorStreamExt {
    /// Wrap a stream of text chunks, returning a stream of redacted chunks.
    fn redact_stream<S, E>(self, stream: S) -> RedactStream<S>
    where
        S: Stream<Item = Result<String, E>>;
}

impl RedactorStreamExt for Redactor {
    fn redact_stream<S, E>(self, stream: S) -> RedactStream<S>
    where
        S: Stream<Item = Result<String, E>>,
    {
        StreamingRedactor::new(self).redact_stream(stream)
    }
}

pin_project! {
    /// A stream that redacts PII from an inner stream of text chunks.
    ///
    /// Created by [`StreamingRedactor::redact_stream`] or [`RedactorStreamExt::redact_stream`].
    pub struct RedactStream<S> {
        #[pin]
        inner: S,
        redactor: Redactor,
        buffer: String,
        done: bool,
    }
}

impl<S, E> RedactStream<S>
where
    S: Stream<Item = Result<String, E>>,
{
    /// Try to flush complete redactable units from the buffer.
    ///
    /// Scans the buffer for whitespace boundaries. When found, the segment
    /// up to (and including) the whitespace is redacted and yielded.
    /// The remaining text stays in the buffer for the next poll.
    fn try_flush(buffer: &mut String, redactor: &Redactor) -> Option<Result<String, E>> {
        // Find the last whitespace position in the buffer
        let last_ws = buffer.char_indices().rev().find_map(|(i, c)| {
            if c.is_whitespace() {
                Some(i + c.len_utf8())
            } else {
                None
            }
        });

        let split_at = last_ws?;

        // Split: flush the part up to and including the whitespace
        let to_flush = buffer[..split_at].to_string();
        let remaining = buffer[split_at..].to_string();
        *buffer = remaining;

        let redacted = redactor.redact(&to_flush).into_owned();
        Some(Ok(redacted))
    }

    /// Flush the remaining buffer, redacting any PII left over.
    fn flush_remaining(buffer: &mut String, redactor: &Redactor) -> Option<Result<String, E>> {
        if buffer.is_empty() {
            return None;
        }
        let remaining = std::mem::take(buffer);
        let redacted = redactor.redact(&remaining).into_owned();
        Some(Ok(redacted))
    }
}

impl<S, E> Stream for RedactStream<S>
where
    S: Stream<Item = Result<String, E>>,
{
    type Item = Result<String, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().project();

        // First, try to flush anything already buffered at safe boundaries
        if let Some(item) = Self::try_flush(this.buffer, this.redactor) {
            return Poll::Ready(Some(item));
        }

        // Poll the inner stream for more data
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.buffer.push_str(&chunk);

                // Try to flush again after accumulating new data
                if let Some(item) = Self::try_flush(this.buffer, this.redactor) {
                    Poll::Ready(Some(item))
                } else {
                    // No safe boundary yet, keep buffering
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(Some(Err(e))) => {
                // On error, flush whatever we have and propagate the error
                if let Some(item) = Self::flush_remaining(this.buffer, this.redactor) {
                    let _ = item;
                }
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                // Stream ended — flush remaining buffer
                *this.done = true;
                if let Some(item) = Self::flush_remaining(this.buffer, this.redactor) {
                    Poll::Ready(Some(item))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (inner_lo, inner_hi) = self.inner.size_hint();
        // We may yield 0..1 extra items from the buffer flush
        (inner_lo, inner_hi.map(|h| h + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::PiiDetector;
    use crate::detectors::{
        credit_card::CreditCardDetector,
        email::EmailDetector,
        ip::{Ipv4Detector, Ipv6Detector},
        phone_number::PhoneNumberDetector,
        ssn::SSNDetector,
    };
    use crate::policy::RedactionPolicy;
    use futures::stream;
    use futures::StreamExt as _;

    fn test_redactor() -> Redactor {
        let detectors: Vec<Box<dyn PiiDetector>> = vec![
            Box::new(EmailDetector::new()),
            Box::new(PhoneNumberDetector::new()),
            Box::new(SSNDetector::new()),
            Box::new(CreditCardDetector::new()),
            Box::new(Ipv4Detector::new()),
            Box::new(Ipv6Detector::new()),
        ];
        Redactor::new(detectors, RedactionPolicy::default())
    }

    #[tokio::test]
    async fn test_stream_no_pii_passthrough() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> =
            vec![Ok("hello ".to_string()), Ok("world".to_string())];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap(), "hello ");
        assert_eq!(results[1].as_ref().unwrap(), "world");
    }

    #[tokio::test]
    async fn test_stream_redacts_pii() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![
            Ok("Email: ".to_string()),
            Ok("test@example.com ".to_string()),
            Ok("for info".to_string()),
        ];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("@"));
        assert!(output.contains(".com"));
        assert!(!output.contains("test@example.com"));
    }

    #[tokio::test]
    async fn test_stream_single_chunk() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![Ok("SSN: 123-45-6789".to_string())];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("███-██-████"));
    }

    #[tokio::test]
    async fn test_stream_flushes_on_end() {
        let sr = StreamingRedactor::new(test_redactor());
        // No whitespace — everything stays buffered until stream ends
        let chunks: Vec<Result<String, std::io::Error>> =
            vec![Ok("Email:".to_string()), Ok("test@example.com".to_string())];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("@"));
        assert!(!output.contains("test@example.com"));
    }

    #[tokio::test]
    async fn test_stream_error_propagation() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![
            Ok("hello ".to_string()),
            Err(std::io::Error::other("test error")),
        ];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
    }

    #[tokio::test]
    async fn test_stream_empty_input() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_stream_many_small_chunks() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = "Contact john@example.com now"
            .chars()
            .map(|c| Ok(c.to_string()))
            .collect();
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("Contact"));
        assert!(output.contains("now"));
        // The email should be redacted
        assert!(!output.contains("john@example.com"));
    }

    #[tokio::test]
    async fn test_stream_credit_card() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![
            Ok("Card: 4111 ".to_string()),
            Ok("1111 1111 1111".to_string()),
        ];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("Card:"));
        assert!(!output.contains("4111 1111 1111 1111"));
    }

    #[tokio::test]
    async fn test_stream_newline_delimited() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![
            Ok("line1\n".to_string()),
            Ok("line2 with test@example.com\n".to_string()),
            Ok("line3\n".to_string()),
        ];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("line1"));
        assert!(output.contains("line3"));
        assert!(!output.contains("test@example.com"));
    }

    #[tokio::test]
    async fn test_stream_redactor_ref() {
        let sr = StreamingRedactor::new(test_redactor());
        assert!(sr.redactor().redact("no pii") == "no pii");
    }

    #[tokio::test]
    async fn test_stream_into_inner() {
        let redactor = test_redactor();
        let sr = StreamingRedactor::new(redactor);
        let inner = sr.into_inner();
        assert!(inner.redact("no pii") == "no pii");
    }

    #[tokio::test]
    async fn test_stream_size_hint() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![
            Ok("a".to_string()),
            Ok("b".to_string()),
            Ok("c".to_string()),
        ];
        let stream = stream::iter(chunks);
        let redacted = sr.redact_stream(stream);
        let (lo, hi) = redacted.size_hint();
        assert_eq!(lo, 3);
        assert_eq!(hi, Some(4)); // 3 + 1 extra from buffer flush
    }

    #[tokio::test]
    async fn test_stream_phone_number() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> = vec![
            Ok("Call ".to_string()),
            Ok("+12025550123".to_string()),
            Ok(" now".to_string()),
        ];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("Call"));
        assert!(!output.contains("+12025550123"));
    }

    #[tokio::test]
    async fn test_stream_ssn() {
        let sr = StreamingRedactor::new(test_redactor());
        let chunks: Vec<Result<String, std::io::Error>> =
            vec![Ok("SSN: 123-".to_string()), Ok("45-6789".to_string())];
        let stream = stream::iter(chunks);
        let results: Vec<_> = sr.redact_stream(stream).collect().await;

        let output: String = results
            .iter()
            .filter_map(|r| r.as_ref().ok().cloned())
            .collect();
        assert!(output.contains("SSN:"));
        assert!(!output.contains("123-45-6789"));
    }
}
