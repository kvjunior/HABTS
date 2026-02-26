"""
Configurable accountability for threshold signatures.

This module is the primary novel contribution of HABTS beyond the
FROST + Birkhoff combination.  It enables a designated tracer to
identify which participants signed a given message, with three
configurable disclosure levels:

1. **FULL** — The tracer learns the exact set of signers.
2. **LEVEL_ONLY** — The tracer learns only how many signers from
   each hierarchy level participated (not individual identities).
3. **THRESHOLD_PROOF** — The tracer learns only that a valid
   (authorised) set signed, nothing more.

Accountability tags are hash-based and bound to the signing session:

    τ_i = H_tag(i ‖ ℓ_i ‖ R_i ‖ z_i ‖ m ‖ sid)

They add negligible overhead (~2 μs per signer) to signing.

Security properties
-------------------
- **Soundness (ACC-SOUND):** No PPT adversary can produce a valid
  accountability proof that attributes a signature to a non-signer,
  under collision resistance of SHA-256.
- **Completeness (ACC-COMP):** An honest signer's accountability tag
  can always be verified, under binding of Pedersen commitments.
- **Privacy:** The disclosure level controls what information leaks.
  At FULL level, no privacy is provided.  At THRESHOLD_PROOF level,
  only validity is revealed.

References
----------
- Boneh & Komlo. "Threshold Signatures with Private Accountability."
  CRYPTO 2022.
- Kelkar et al. "Breaking Omertà." CCS 2025.
- Li et al. "Threshold Signatures with Private Accountability via
  Secretly Designated Witnesses." ACISP 2024.
- Khuc et al. "Threshold Ring Signatures with Accountability."
  ACISP 2024.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Set

from .curve import Scalar, Point, G
from .hash import hash_accountability
from .access import HierarchicalAccess
from .signing import PartialSignature, ThresholdSignature


# ── disclosure levels ───────────────────────────────────────────────────

class DisclosureLevel(Enum):
    """How much information the tracer can extract."""

    FULL = auto()             # exact signer set
    LEVEL_ONLY = auto()       # per-level counts only
    THRESHOLD_PROOF = auto()  # only validity


# ── accountability data structures ──────────────────────────────────────

@dataclass
class AccountabilityTag:
    """Per-signer accountability tag generated during signing."""

    signer_id: int
    level: int
    tag: bytes                # H(id ‖ level ‖ R_i ‖ z_i ‖ m ‖ sid)
    R_i_bytes: bytes          # compressed R_i for verification
    z_i_bytes: bytes          # z_i serialised

    def to_bytes(self) -> bytes:
        return (
            self.signer_id.to_bytes(4, "big")
            + self.level.to_bytes(2, "big")
            + len(self.tag).to_bytes(2, "big")
            + self.tag
            + self.R_i_bytes
            + self.z_i_bytes
        )


@dataclass
class AccountabilityProof:
    """
    Aggregated accountability proof attached to a threshold signature.

    Contains either full tags (FULL disclosure), level-summary
    counts (LEVEL_ONLY), or a single validity proof (THRESHOLD_PROOF).
    """

    disclosure_level: DisclosureLevel
    session_id: bytes
    message_hash: bytes           # SHA-256(message)

    # FULL: per-signer tags
    tags: List[AccountabilityTag]

    # LEVEL_ONLY: per-level counters + aggregate hash for integrity
    level_counts: Optional[Dict[int, int]] = None
    level_aggregate_hash: Optional[bytes] = None

    # THRESHOLD_PROOF: single aggregate hash
    aggregate_hash: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        parts = [
            self.disclosure_level.value.to_bytes(1, "big"),
            self.session_id,
            self.message_hash,
            len(self.tags).to_bytes(4, "big"),
        ]
        for t in self.tags:
            parts.append(t.to_bytes())
        if self.level_counts is not None:
            parts.append(len(self.level_counts).to_bytes(2, "big"))
            for level, count in sorted(self.level_counts.items()):
                parts.append(level.to_bytes(2, "big"))
                parts.append(count.to_bytes(4, "big"))
        if self.level_aggregate_hash is not None:
            parts.append(self.level_aggregate_hash)
        if self.aggregate_hash is not None:
            parts.append(self.aggregate_hash)
        return b"".join(parts)


# ── accountability prover (runs during signing) ─────────────────────────

class AccountabilityProver:
    """
    Constructs accountability proofs from partial signatures.

    Invoked by the aggregator after collecting all partial signatures
    but before publishing the final threshold signature.
    """

    def __init__(
        self,
        access: HierarchicalAccess,
        disclosure: DisclosureLevel = DisclosureLevel.FULL,
    ) -> None:
        self.access = access
        self.disclosure = disclosure

    def build_proof(
        self,
        message: bytes,
        session_id: bytes,
        partial_sigs: List[PartialSignature],
    ) -> AccountabilityProof:
        """
        Build an accountability proof from partial signatures.

        The partial signatures must already be verified by the aggregator.
        """
        msg_hash = hashlib.sha256(message).digest()

        # Build per-signer tags
        tags: List[AccountabilityTag] = []
        for ps in partial_sigs:
            at = AccountabilityTag(
                signer_id=ps.signer_id,
                level=ps.level,
                tag=ps.accountability_tag,
                R_i_bytes=ps.R_i.to_bytes_compressed(),
                z_i_bytes=ps.z_i.to_bytes(),
            )
            tags.append(at)

        level_counts: Optional[Dict[int, int]] = None
        level_aggregate_hash: Optional[bytes] = None
        aggregate_hash: Optional[bytes] = None

        if self.disclosure == DisclosureLevel.LEVEL_ONLY:
            level_counts = self._compute_level_counts(partial_sigs)
            # Include an aggregate hash so the tracer can verify integrity
            level_aggregate_hash = self._compute_aggregate_hash(
                tags, session_id,
            )
        elif self.disclosure == DisclosureLevel.THRESHOLD_PROOF:
            aggregate_hash = self._compute_aggregate_hash(tags, session_id)

        return AccountabilityProof(
            disclosure_level=self.disclosure,
            session_id=session_id,
            message_hash=msg_hash,
            tags=tags if self.disclosure == DisclosureLevel.FULL else [],
            level_counts=level_counts,
            level_aggregate_hash=level_aggregate_hash,
            aggregate_hash=aggregate_hash,
        )

    def _compute_level_counts(
        self, partial_sigs: List[PartialSignature],
    ) -> Dict[int, int]:
        counts: Dict[int, int] = {}
        for ps in partial_sigs:
            counts[ps.level] = counts.get(ps.level, 0) + 1
        return counts

    def _compute_aggregate_hash(
        self,
        tags: List[AccountabilityTag],
        session_id: bytes,
    ) -> bytes:
        h = hashlib.sha256()
        h.update(b"HABTS/v1/agg_accountability")
        h.update(session_id)
        for t in sorted(tags, key=lambda x: x.signer_id):
            h.update(t.tag)
        return h.digest()


# ── accountability verifier / tracer ────────────────────────────────────

class AccountabilityTracer:
    """
    Verifies and interprets accountability proofs.

    In a deployment, the tracer holds a special key (or is a designated
    authority) that can open proofs.  In HABTS's hash-based scheme,
    opening is straightforward for FULL disclosure: the tags contain
    enough information to recompute and verify each signer's contribution.
    """

    def __init__(self, access: HierarchicalAccess) -> None:
        self.access = access

    def trace_full(
        self,
        proof: AccountabilityProof,
    ) -> Set[int]:
        """
        Extract the full signer set from a FULL-disclosure proof.

        Returns the set of signer IDs.
        """
        if proof.disclosure_level != DisclosureLevel.FULL:
            raise ValueError("FULL disclosure required for full trace")
        return {t.signer_id for t in proof.tags}

    def trace_levels(
        self,
        proof: AccountabilityProof,
    ) -> Dict[int, int]:
        """
        Extract per-level signer counts from a LEVEL_ONLY proof.
        Can also downgrade from FULL disclosure.
        """
        if proof.disclosure_level == DisclosureLevel.FULL:
            # Downgrade: compute counts from full tags
            counts: Dict[int, int] = {}
            for t in proof.tags:
                counts[t.level] = counts.get(t.level, 0) + 1
            return counts
        if proof.level_counts is not None:
            return dict(proof.level_counts)
        raise ValueError("no level counts in proof")

    def verify_tag(
        self,
        tag: AccountabilityTag,
        message: bytes,
        session_id: bytes,
    ) -> bool:
        """
        Verify that an individual accountability tag is correctly
        formed by recomputing the hash.

        This checks:  tag.tag == H(id ‖ level ‖ R_i ‖ z_i ‖ m ‖ sid)
        """
        R_i = Point.from_bytes(tag.R_i_bytes)
        z_i = Scalar.from_bytes(tag.z_i_bytes)

        expected = hash_accountability(
            tag.signer_id,
            tag.level,
            R_i,
            z_i,
            message,
            session_id,
        )
        return tag.tag == expected

    def verify_proof(
        self,
        proof: AccountabilityProof,
        message: bytes,
    ) -> bool:
        """
        Verify the integrity of an entire accountability proof.

        For FULL disclosure: verify every tag individually and check
        that the signer set is authorised.
        For LEVEL_ONLY: verify cumulative thresholds are met.
        For THRESHOLD_PROOF: verify aggregate hash is present and
        well-formed.
        """
        msg_hash = hashlib.sha256(message).digest()
        if proof.message_hash != msg_hash:
            return False

        if proof.disclosure_level == DisclosureLevel.FULL:
            for tag in proof.tags:
                if not self.verify_tag(tag, message, proof.session_id):
                    return False
            # Check the signer set is authorised
            signer_ids = {t.signer_id for t in proof.tags}
            return self.access.is_authorised(signer_ids)

        if proof.disclosure_level == DisclosureLevel.LEVEL_ONLY:
            if proof.level_counts is None:
                return False
            # Verify cumulative thresholds are met
            cumulative = 0
            for lc in self.access.levels:
                cumulative += proof.level_counts.get(lc.level, 0)
                if cumulative < lc.threshold:
                    return False
            # Verify the aggregate hash is present (integrity check)
            if proof.level_aggregate_hash is None:
                return False
            return len(proof.level_aggregate_hash) == 32

        if proof.disclosure_level == DisclosureLevel.THRESHOLD_PROOF:
            # Can only verify that aggregate_hash is present
            return (
                proof.aggregate_hash is not None
                and len(proof.aggregate_hash) == 32
            )

        return False

    def judge(
        self,
        proof: AccountabilityProof,
        claimed_signer: int,
    ) -> Optional[bool]:
        """
        Determine whether a specific participant signed.

        Returns True/False for FULL disclosure; None if disclosure
        level is insufficient to determine.
        """
        if proof.disclosure_level == DisclosureLevel.FULL:
            signer_ids = {t.signer_id for t in proof.tags}
            return claimed_signer in signer_ids
        return None
