// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nymora-core` — shared types, wire formats, `agora_id` derivation, and errors for the
//! Nymora protocol.
//!
//! Scaffold established in Step 1 (see `../SETUP.md`). No protocol logic yet.

/// Crate scaffold marker. Replaced by real protocol types in later steps.
pub const SCAFFOLD: &str = "nymora-core";

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_builds() {
        assert_eq!(super::SCAFFOLD, "nymora-core");
    }
}
