// SPDX-License-Identifier: MIT OR Apache-2.0

//! Errors.
//!
//! # Errors are a side channel
//!
//! Idiomatic Rust favours precise, actionable errors. Here precision can leak: an error
//! that distinguishes "no such credential" from "that credential is revoked" answers a
//! question about hidden state to whoever asked, and the specification is at pains not to
//! answer it (§5.2, §5.3, §11).
//!
//! The rule this module applies is narrower and more useful than "make everything vague":
//!
//! > **An error may distinguish cases only when the distinction follows from the caller's
//! > own input, never from hidden protocol state.**
//!
//! Whether a message decoded is a property of the bytes the caller sent — telling them so
//! reveals nothing they did not already know. Whether a credential is revoked, a nullifier
//! already spent, or a threshold met are properties of state they are not entitled to
//! observe, and every one of them must produce the same [`ProtocolError::Rejected`].
//!
//! # What the rule protects
//!
//! It governs what crosses to a **counterparty**, not what a party knows about itself.
//! A Skiora legitimately knows which credentials it has revoked; the constraint is that its
//! *response* must not disclose that. Local diagnostics are therefore encouraged — see
//! [`Rejection`] — and are simply unable to reach the wire, because only [`ProtocolError`]
//! is ever encoded into a response.

/// An error safe to return across a trust boundary.
///
/// This type is deliberately tiny, and **adding a variant widens what a counterparty can
/// distinguish**. The exhaustiveness test in this module will stop compiling if the set
/// changes, which is the intended friction: a new variant needs a specification argument
/// first, not just a use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    /// The input did not decode.
    ///
    /// Safe to distinguish: malformedness is a property of the bytes the caller supplied,
    /// so reporting it tells them nothing about protocol state.
    Malformed,

    /// The request was refused.
    ///
    /// Every refusal arising from protocol state produces this and nothing more —
    /// unknown credential, revoked credential, duplicate nullifier, invalid proof,
    /// unmet threshold, wrong epoch. They are indistinguishable by construction, not by
    /// convention: see [`Rejection`], which is the only way to build one and which discards
    /// its reason on the way.
    Rejected,

    /// The operation could not be attempted.
    ///
    /// Transient or operational — storage unreachable, an authenticator declined to act.
    /// Carries no protocol state.
    Unavailable,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // These strings cross the boundary. Keep them constant per variant: a message that
        // varied with the underlying cause would reintroduce exactly what the type removes.
        f.write_str(match self {
            Self::Malformed => "malformed",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
        })
    }
}

impl core::error::Error for ProtocolError {}

macro_rules! local_reasons {
    ($( $(#[$doc:meta])* $variant:ident ),+ $(,)?) => {
        /// Why something was rejected — **local diagnostics only**.
        ///
        /// Never encoded, never returned to a counterparty. There is deliberately no
        /// serializer for this type, so the wire format (§6.6) cannot carry it even by
        /// accident.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum LocalReason {
            $( $(#[$doc])* $variant, )+
        }

        impl LocalReason {
            /// Every reason, exhaustively. Generated from the same list as the enum.
            pub const ALL: &'static [LocalReason] = &[ $( LocalReason::$variant, )+ ];
        }
    };
}

local_reasons! {
    /// No credential matches the presented material.
    UnknownCredential,
    /// The credential is no longer in good standing (§11).
    CredentialRevoked,
    /// This nullifier has already been recorded in this context (§5.3).
    DuplicateNullifier,
    /// The zero-knowledge proof did not verify.
    ProofInvalid,
    /// The vouching threshold has not been reached (§5.3).
    ThresholdNotMet,
    /// The referenced epoch is outside the acceptable window.
    EpochOutOfRange,
    /// The credential does not satisfy the target policy class (§5.1).
    PolicyDenied,
    /// The material belongs to a different agora (§16.1).
    WrongAgora,
    /// The presented witness-service key is not the current epoch's (§5.2, proposal 0025).
    WitnessKeyStale,
    /// The agora has been dissolved (§12).
    Dissolved,
}

/// A refusal, carrying an optional reason for local use.
///
/// Construct rejections with [`Rejection::because`] so the reason is available to logs,
/// tests, and a developer at a debugger — then convert to [`ProtocolError`] at the
/// boundary, which discards it. The narrowing is one-way and total: every reason becomes
/// [`ProtocolError::Rejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    reason: Option<LocalReason>,
}

impl Rejection {
    /// A refusal with no recorded reason.
    #[must_use]
    pub const fn opaque() -> Self {
        Self { reason: None }
    }

    /// A refusal that records why, for local diagnostics.
    #[must_use]
    pub const fn because(reason: LocalReason) -> Self {
        Self {
            reason: Some(reason),
        }
    }

    /// The recorded reason, if any.
    ///
    /// Callers must not place the result in anything that leaves the process boundary
    /// toward a counterparty.
    #[must_use]
    pub const fn local_reason(&self) -> Option<LocalReason> {
        self.reason
    }
}

impl core::fmt::Display for Rejection {
    /// Renders coarsely, discarding the reason.
    ///
    /// `Debug` shows the reason because it is a developer-facing view of local state;
    /// `Display` is what tends to end up in a message someone forwards, so it says only
    /// what [`ProtocolError`] would.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("rejected")
    }
}

impl core::error::Error for Rejection {}

impl From<Rejection> for ProtocolError {
    fn from(_: Rejection) -> Self {
        Self::Rejected
    }
}

impl From<LocalReason> for Rejection {
    fn from(reason: LocalReason) -> Self {
        Self::because(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalReason, ProtocolError, Rejection};
    use std::format;

    /// Fails to compile if a variant is added or removed.
    ///
    /// Widening this enum widens what a counterparty can distinguish about hidden state.
    /// If you are here because this stopped compiling, the change needs an argument in the
    /// specification before it needs one in the code.
    fn _the_boundary_error_set_is_closed(error: ProtocolError) {
        match error {
            ProtocolError::Malformed | ProtocolError::Rejected | ProtocolError::Unavailable => {}
        }
    }

    #[test]
    fn every_reason_narrows_to_one_indistinguishable_error() {
        for reason in LocalReason::ALL {
            let narrowed = ProtocolError::from(Rejection::because(*reason));
            assert_eq!(
                narrowed,
                ProtocolError::Rejected,
                "{reason:?} produced a distinguishable error"
            );
        }
    }

    #[test]
    fn narrowing_discards_the_reason() {
        for reason in LocalReason::ALL {
            let rendered = format!("{}", ProtocolError::from(Rejection::because(*reason)));
            assert_eq!(rendered, "rejected", "{reason:?} leaked through Display");
        }
    }

    #[test]
    fn rejection_display_is_constant_across_reasons() {
        let opaque = format!("{}", Rejection::opaque());
        for reason in LocalReason::ALL {
            assert_eq!(
                format!("{}", Rejection::because(*reason)),
                opaque,
                "{reason:?} is distinguishable through Display"
            );
        }
    }

    #[test]
    fn reason_survives_locally() {
        let rejection = Rejection::because(LocalReason::CredentialRevoked);
        assert_eq!(
            rejection.local_reason(),
            Some(LocalReason::CredentialRevoked)
        );
        assert!(format!("{rejection:?}").contains("CredentialRevoked"));
    }

    #[test]
    fn protocol_error_messages_are_fixed() {
        assert_eq!(format!("{}", ProtocolError::Malformed), "malformed");
        assert_eq!(format!("{}", ProtocolError::Rejected), "rejected");
        assert_eq!(format!("{}", ProtocolError::Unavailable), "unavailable");
    }
}
