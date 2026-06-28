//! Slot and epoch arithmetic for Solana-based scheduling.
//!
//! Whitepaper §5: "Every action carries an expiration window in the proof's
//! public inputs. Outside the window the proof is invalid — closing the replay
//! vector that makes unattended agents dangerous."
//!
//! This module gives every layer of the stack a consistent vocabulary for
//! slot/epoch reasoning without depending on the Solana SDK.

/// Solana mainnet: ~400 ms per slot, 432,000 slots per epoch.
pub const SLOTS_PER_EPOCH: u64 = 432_000;
/// Default validity window for a single inference job (≈ 2 minutes).
pub const DEFAULT_JOB_WINDOW: u64 = 300;
/// Minimum window a provider must honour (prevents tiny windows that expire in transit).
pub const MIN_JOB_WINDOW: u64 = 20;

/// An absolute Solana slot.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Slot(pub u64);

impl Slot {
    pub fn epoch(&self) -> Epoch {
        Epoch(self.0 / SLOTS_PER_EPOCH)
    }

    pub fn offset_in_epoch(&self) -> u64 {
        self.0 % SLOTS_PER_EPOCH
    }

    pub fn advance(&self, n: u64) -> Self {
        Slot(self.0.saturating_add(n))
    }

    pub fn saturating_sub(&self, n: u64) -> Self {
        Slot(self.0.saturating_sub(n))
    }

    /// Default expiry slot for a job submitted at this slot.
    pub fn default_expiry(&self) -> Self {
        self.advance(DEFAULT_JOB_WINDOW)
    }
}

impl From<u64> for Slot {
    fn from(v: u64) -> Self { Slot(v) }
}

impl From<Slot> for u64 {
    fn from(s: Slot) -> Self { s.0 }
}

/// An epoch number (group of [`SLOTS_PER_EPOCH`] slots).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Epoch(pub u64);

impl Epoch {
    pub fn start_slot(&self) -> Slot {
        Slot(self.0 * SLOTS_PER_EPOCH)
    }

    pub fn end_slot(&self) -> Slot {
        Slot((self.0 + 1) * SLOTS_PER_EPOCH)
    }

    pub fn next(&self) -> Self {
        Epoch(self.0 + 1)
    }
}

/// Validate that a `[start, end)` validity window is sane.
#[derive(Debug, PartialEq, Eq)]
pub enum WindowError {
    /// `end ≤ start` — window is empty or inverted.
    Empty,
    /// `end - start < MIN_JOB_WINDOW` — too narrow to survive network latency.
    TooNarrow,
}

pub fn validate_window(start: u64, end: u64) -> Result<(), WindowError> {
    if end <= start {
        return Err(WindowError::Empty);
    }
    if end - start < MIN_JOB_WINDOW {
        return Err(WindowError::TooNarrow);
    }
    Ok(())
}

/// Whether `current_slot` falls inside a `[start, end)` window.
pub fn is_valid_at(start: u64, end: u64, current_slot: u64) -> bool {
    current_slot >= start && current_slot < end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_arithmetic() {
        let s = Slot(432_001);
        assert_eq!(s.epoch(), Epoch(1));
        assert_eq!(s.offset_in_epoch(), 1);
        assert_eq!(Epoch(2).start_slot(), Slot(864_000));
    }

    #[test]
    fn window_validation() {
        assert!(validate_window(100, 200).is_ok());
        assert_eq!(validate_window(200, 100), Err(WindowError::Empty));
        assert_eq!(validate_window(100, 110), Err(WindowError::TooNarrow));
    }

    #[test]
    fn is_valid_at_boundaries() {
        assert!(!is_valid_at(10, 20, 9));
        assert!(is_valid_at(10, 20, 10));
        assert!(is_valid_at(10, 20, 19));
        assert!(!is_valid_at(10, 20, 20));
    }
}
