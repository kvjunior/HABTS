"""
High-level HABTS protocol orchestration.

Provides a single ``HABTSProtocol`` class that ties together DKG,
signing, verification, and accountability tracing into a clean API
suitable for both benchmarking and integration testing.

Usage
-----
::

    from habts.protocol import HABTSProtocol

    # Setup
    proto = HABTSProtocol.setup(
        level_sizes=[2, 3, 5],
        thresholds=[1, 3, 7],
    )

    # Sign
    sig = proto.sign(b"hello world", signer_ids=[1, 2, 4, 5, 7, 8, 9])

    # Verify
    assert proto.verify(b"hello world", sig)

    # Trace (if accountability is enabled)
    signers = proto.trace(b"hello world", sig)
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .curve import Scalar, Point, G
from .access import HierarchicalAccess
from .dkg import DKGResult, run_dkg
from .signing import (
    Signer,
    Aggregator,
    NonceCommitment,
    ThresholdSignature,
    verify_signature,
)
from .accountability import (
    AccountabilityProver,
    AccountabilityTracer,
    AccountabilityProof,
    DisclosureLevel,
)


@dataclass
class SignatureBundle:
    """A threshold signature with optional accountability proof."""

    signature: ThresholdSignature
    accountability_proof: Optional[AccountabilityProof] = None


class HABTSProtocol:
    """
    End-to-end HABTS protocol.

    Encapsulates the full lifecycle:
    1. Setup — define hierarchy and run DKG.
    2. Sign — two-round threshold signing with accountability.
    3. Verify — standard Schnorr verification.
    4. Trace — extract signer information from accountability proof.
    """

    def __init__(
        self,
        dkg_result: DKGResult,
        disclosure: DisclosureLevel = DisclosureLevel.FULL,
    ) -> None:
        self._dkg = dkg_result
        self._access = dkg_result.access_structure
        self._pk = dkg_result.group_public_key
        self._disclosure = disclosure
        self._public_shares = dkg_result.public_shares

        # Create Signer objects for each participant
        self._signers: Dict[int, Signer] = {}
        for pid, share in dkg_result.participant_shares.items():
            self._signers[pid] = Signer(
                participant_id=pid,
                secret_share=share,
                access=self._access,
            )

        # Aggregator with public shares for partial signature verification
        self._aggregator = Aggregator(
            self._pk, self._access, self._public_shares,
        )
        self._prover = AccountabilityProver(self._access, disclosure)
        self._tracer = AccountabilityTracer(self._access)

    # ── factories ──────────────────────────────────────────────────────

    @classmethod
    def setup(
        cls,
        level_sizes: List[int],
        thresholds: List[int],
        disclosure: DisclosureLevel = DisclosureLevel.FULL,
    ) -> HABTSProtocol:
        """
        Create a new HABTS instance: define hierarchy and run DKG.

        Parameters
        ----------
        level_sizes : list[int]
            Number of participants per level.
        thresholds : list[int]
            Cumulative thresholds per level (non-decreasing).
        disclosure : DisclosureLevel
            Accountability disclosure level.
        """
        access = HierarchicalAccess.create(level_sizes, thresholds)
        dkg_result = run_dkg(access)
        return cls(dkg_result, disclosure)

    @classmethod
    def setup_flat(
        cls,
        n: int,
        t: int,
        disclosure: DisclosureLevel = DisclosureLevel.FULL,
    ) -> HABTSProtocol:
        """Flat (non-hierarchical) t-of-n threshold."""
        access = HierarchicalAccess.flat(n, t)
        dkg_result = run_dkg(access)
        return cls(dkg_result, disclosure)

    # ── signing ────────────────────────────────────────────────────────

    def sign(
        self,
        message: bytes,
        signer_ids: Optional[List[int]] = None,
    ) -> SignatureBundle:
        """
        Execute the full two-round signing protocol.

        Parameters
        ----------
        message : bytes
            The message to sign.
        signer_ids : list[int] or None
            Which participants sign.  If None, uses the minimum
            authorised set (first ``overall_threshold`` participants).
        """
        if signer_ids is None:
            signer_ids = self.select_default_signers()

        signer_ids = sorted(signer_ids)

        if not self._access.is_authorised(set(signer_ids)):
            raise ValueError("signer set not authorised")
        if not self._access.check_signer_set_valid(signer_ids):
            raise ValueError(
                "signer set violates Pólya conditions for Birkhoff "
                "interpolation"
            )

        session_id = secrets.token_bytes(32)

        # Round 1: generate nonces
        commitments: Dict[int, NonceCommitment] = {}
        for pid in signer_ids:
            commitments[pid] = self._signers[pid].generate_nonce()

        # Round 2: compute partial signatures
        partial_sigs = []
        for pid in signer_ids:
            ps = self._signers[pid].sign(
                message=message,
                session_id=session_id,
                commitments=commitments,
                signer_ids=signer_ids,
                group_public_key=self._pk,
            )
            partial_sigs.append(ps)

        # Aggregate (includes per-signer verification)
        sig = self._aggregator.aggregate(
            message=message,
            session_id=session_id,
            commitments=commitments,
            partial_sigs=partial_sigs,
        )

        # Build accountability proof
        proof = self._prover.build_proof(
            message=message,
            session_id=session_id,
            partial_sigs=partial_sigs,
        )

        return SignatureBundle(signature=sig, accountability_proof=proof)

    # ── verification ───────────────────────────────────────────────────

    def verify(self, message: bytes, bundle: SignatureBundle) -> bool:
        """
        Verify a threshold signature.

        This is standard Schnorr verification — no threshold or
        hierarchy information is needed.
        """
        return verify_signature(self._pk, message, bundle.signature)

    # ── tracing ────────────────────────────────────────────────────────

    def trace(
        self,
        message: bytes,
        bundle: SignatureBundle,
    ) -> Optional[Set[int]]:
        """
        Extract signer set from accountability proof (FULL disclosure).

        Returns None if disclosure level is insufficient.
        """
        if bundle.accountability_proof is None:
            return None
        proof = bundle.accountability_proof
        if proof.disclosure_level == DisclosureLevel.FULL:
            if self._tracer.verify_proof(proof, message):
                return self._tracer.trace_full(proof)
        return None

    def trace_levels(
        self,
        message: bytes,
        bundle: SignatureBundle,
    ) -> Optional[Dict[int, int]]:
        """
        Extract per-level signer counts (LEVEL_ONLY or FULL).
        """
        if bundle.accountability_proof is None:
            return None
        proof = bundle.accountability_proof
        if proof.disclosure_level in (
            DisclosureLevel.FULL,
            DisclosureLevel.LEVEL_ONLY,
        ):
            if self._tracer.verify_proof(proof, message):
                return self._tracer.trace_levels(proof)
        return None

    # ── signer set selection ───────────────────────────────────────────

    def select_default_signers(self) -> List[int]:
        """
        Select the minimum authorised set of signers.

        Greedily selects participants from highest authority (level 0)
        first, filling cumulative thresholds at each level.
        """
        all_ids = self._access.all_participant_ids()
        return all_ids[: self._access.overall_threshold]

    # ── accessors ──────────────────────────────────────────────────────

    @property
    def group_public_key(self) -> Point:
        return self._pk

    @property
    def access_structure(self) -> HierarchicalAccess:
        return self._access

    @property
    def num_participants(self) -> int:
        return self._access.num_participants

    @property
    def overall_threshold(self) -> int:
        return self._access.overall_threshold

    @property
    def public_shares(self) -> Dict[int, Point]:
        return dict(self._public_shares)

    def __repr__(self) -> str:
        return (
            f"HABTSProtocol({self._access}, "
            f"disclosure={self._disclosure.name})"
        )
