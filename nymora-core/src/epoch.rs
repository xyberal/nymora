// SPDX-License-Identifier: MIT OR Apache-2.0

//! Epoch numbering.

/// An agora's epoch counter (§9.1).
///
/// Epochs are supplied to the engine as a parameter rather than read from a clock: the
/// engine is sans-io and owns no notion of time. Each agora keeps its own schedule, and
/// epoch numbers from different agoras are unrelated (§16.1).
///
/// An epoch number never appears in an external bundle (§6.6); a verifier resolves the
/// relevant epoch through the tag mechanism instead (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(u64);

impl Epoch {
    /// The first epoch of an agora.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw epoch number.
    #[must_use]
    pub const fn new(number: u64) -> Self {
        Self(number)
    }

    /// The raw epoch number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next epoch, or `None` on overflow.
    ///
    /// Rollover is checked rather than wrapping: an epoch counter that silently returned to
    /// zero would cause previously-used per-epoch values to be re-derived, and with them
    /// nullifiers that must never repeat.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }
}

impl core::fmt::Display for Epoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Epoch;

    #[test]
    fn counts_upward() {
        assert_eq!(Epoch::ZERO.get(), 0);
        assert_eq!(Epoch::ZERO.next(), Some(Epoch::new(1)));
    }

    #[test]
    fn rollover_is_checked_not_wrapping() {
        assert_eq!(Epoch::new(u64::MAX).next(), None);
    }

    #[test]
    fn orders_numerically() {
        assert!(Epoch::new(1) < Epoch::new(2));
    }
}
