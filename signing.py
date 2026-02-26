"""
Two-round threshold Schnorr signing with Birkhoff coefficients.

This is the FROST protocol [Komlo-Goldberg, SAC 2020] with Lagrange
coefficients replaced by Birkhoff coefficients for hierarchical access
control [Tassa, J. Cryptology 2007].  The algebraic structure is
identical: each signer computes a partial Schnorr response, and the
aggregator combines them into a standard Schnorr signature verifiable
with the group public key.

**Round 1 (preprocessing):**  Each signer samples nonce pair (d, e)
and broadcasts commitments  (D = d·G,  E = e·G).

**Round 2 (signing):**  Given message *m* and all commitments:

    ρ_i = H₁(i, m, B)                    (binding factor)
    R   = Σ (D_i + ρ_i · E_i)            (aggregate nonce)
    c   = H₂(R, Y, m)                    (Schnorr challenge)
    z_i = d_i + ρ_i · e_i + c · λ_i · s_i    (partial response)

where  λ_i  is the **Birkhoff coefficient** (not Lagrange), and  s_i
is the signer's Birkhoff derivative share.

The final signature  (R, z = Σ z_i)  is a standard Schnorr signature.

Security
--------
EUF-CMA under OMDL in the ROM (selective corruption, up to t−1
corruptions).  This follows from FROST's security proof [KG20, BKLN22]
because the Birkhoff coefficient substitution preserves the algebraic
structure needed for secret reconstruction.

References
----------
- Komlo, Goldberg (2020). "FROST: Flexible Round-Optimized Schnorr
  Threshold Signatures."  SAC 2020.
- Bellare, Crites, Komlo, Maller, Tessaro, Zhu (2022). "Better Than
  Advertised Security for Non-Interactive Threshold Signatures."
  CRYPTO 2022.
- Crites, Katz, Komlo, Tessaro, Zhu (2025). "On the Adaptive
  Security of FROST."  CRYPTO 2025.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .curve import Scalar, Point, G
from .hash import hash_binding, hash_sig, hash_accountability
from .polynomial import (
    all_birkhoff_coefficients,
    check_polya_conditions,
    BirkhoffPoint,
)
from .access import HierarchicalAccess


# ── data structures ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class NonceCommitment:
    """Public nonce commitment  (D, E)  broadcast in Round 1."""

    signer_id: int
    D: Point       # D = d · G
    E: Point       # E = e · G

    def to_bytes(self) -> bytes:
        return (
            self.signer_id.to_bytes(4, "big")
            + self.D.to_bytes_compressed()
            + self.E.to_bytes_compressed()
        )


@dataclass
class NoncePair:
    """Secret nonce pair — MUST be used exactly once, then erased."""

    d: Scalar
    e: Scalar
    used: bool = False

    def mark_used(self) -> None:
        if self.used:
            raise RuntimeError("nonce reuse detected — CRITICAL SECURITY")
        self.used = True

    def clear(self) -> None:
        """Overwrite secrets (best-effort in Python)."""
        self.d = Scalar.zero()
        self.e = Scalar.zero()


@dataclass(frozen=True)
class PartialSignature:
    """A signer's Round 2 output."""

    signer_id: int
    level: int
    z_i: Scalar                       # partial Schnorr response
    R_i: Point                        # signer's aggregated nonce point
    accountability_tag: bytes          # H(i ‖ ℓ ‖ R_i ‖ z_i ‖ m ‖ sid)
    session_id: bytes


@dataclass(frozen=True)
class ThresholdSignature:
    """
    Final aggregated threshold signature  (R, z).

    Verifiable as a standard Schnorr signature:
        z·G  ==  R + c·Y   where  c = H(R, Y, m).
    """

    R: Point
    z: Scalar

    def to_bytes(self) -> bytes:
        """Serialise to 65 bytes: compressed R (33) + z (32)."""
        return self.R.to_bytes_compressed() + self.z.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> ThresholdSignature:
        if len(data) != 65:
            raise ValueError(f"expected 65 bytes, got {len(data)}")
        R = Point.from_bytes(data[:33])
        z = Scalar.from_bytes(data[33:65])
        return cls(R=R, z=z)


# ── signer ──────────────────────────────────────────────────────────────

class Signer:
    """
    Protocol state for a single threshold signer.

    Lifecycle per signing session:
    1. ``generate_nonce()``  → returns ``NonceCommitment``
    2. ``sign(…)``           → returns ``PartialSignature``
    """

    def __init__(
        self,
        participant_id: int,
        secret_share: Scalar,
        access: HierarchicalAccess,
    ) -> None:
        self.id = participant_id
        self.share = secret_share
        self.access = access
        self.level = access.get_level(participant_id)

        self._nonce: Optional[NoncePair] = None

    def generate_nonce(self) -> NonceCommitment:
        """
        Round 1: sample fresh nonce pair and return the public commitment.

        **Must** be called once per signing session.
        """
        d = Scalar.random()
        e = Scalar.random()
        self._nonce = NoncePair(d=d, e=e)

        return NonceCommitment(
            signer_id=self.id,
            D=d * G,
            E=e * G,
        )

    def sign(
        self,
        message: bytes,
        session_id: bytes,
        commitments: Dict[int, NonceCommitment],
        signer_ids: List[int],
        group_public_key: Point,
    ) -> PartialSignature:
        """
        Round 2: compute partial Schnorr response.

        Parameters
        ----------
        message : bytes
            Message being signed.
        session_id : bytes
            Unique session identifier.
        commitments : dict
            Nonce commitments from all signers (including self).
        signer_ids : list[int]
            Sorted list of participating signer IDs.
        group_public_key : Point
            The group public key *Y* from DKG.
        """
        if self._nonce is None:
            raise RuntimeError("no nonce — call generate_nonce() first")
        if self._nonce.used:
            raise RuntimeError("nonce already used")
        if self.id not in signer_ids:
            raise ValueError("signer not in participant set")

        self._nonce.mark_used()
        nonce = self._nonce

        # binding data: ordered commitments
        binding_data = _compute_binding_data(
            session_id, message, commitments, signer_ids,
        )

        # per-signer binding factor
        rho_i = hash_binding(self.id, message, binding_data)

        # this signer's nonce point:  R_i = D_i + ρ_i · E_i
        R_i = nonce.d * G + rho_i * (nonce.e * G)

        # aggregate nonce R = Σ (D_j + ρ_j · E_j)
        R = _compute_aggregate_nonce(
            message, binding_data, commitments, signer_ids,
        )

        # Schnorr challenge
        c = hash_sig(R, group_public_key, message)

        # Birkhoff coefficients for the signer set
        bk_points = self.access.get_birkhoff_points(signer_ids)
        lambdas = all_birkhoff_coefficients(signer_ids, bk_points)
        idx = signer_ids.index(self.id)
        lambda_i = lambdas[idx]

        # partial signature:  z_i = d + ρ·e + c·λ·s
        z_i = nonce.d + rho_i * nonce.e + c * lambda_i * self.share

        # accountability tag
        tag = hash_accountability(
            self.id, self.level, R_i, z_i, message, session_id,
        )

        # clear nonce — CRITICAL: prevent reuse
        self._nonce = None
        nonce.clear()

        return PartialSignature(
            signer_id=self.id,
            level=self.level,
            z_i=z_i,
            R_i=R_i,
            accountability_tag=tag,
            session_id=session_id,
        )


# ── aggregator ──────────────────────────────────────────────────────────

class Aggregator:
    """
    Combines partial signatures into a full threshold Schnorr signature.

    The aggregator is **not** trusted for unforgeability — it only needs
    to be trusted for liveness (it could refuse to combine).

    The aggregator DOES verify each partial signature individually
    using the signers' public shares.  This enables identification of
    misbehaving signers (critical for accountability).
    """

    def __init__(
        self,
        group_public_key: Point,
        access: HierarchicalAccess,
        public_shares: Dict[int, Point],
    ) -> None:
        self.pk = group_public_key
        self.access = access
        self.public_shares = public_shares

    def aggregate(
        self,
        message: bytes,
        session_id: bytes,
        commitments: Dict[int, NonceCommitment],
        partial_sigs: List[PartialSignature],
    ) -> ThresholdSignature:
        """
        Combine partial signatures and verify the result.

        Each partial signature is verified individually:
            z_i · G  ==  R_i  +  c · λ_i · Y_i

        where Y_i = s_i · G is the signer's public share.

        This enables the aggregator to identify exactly which signer
        produced an invalid partial signature.

        Raises ``ValueError`` if any partial signature is invalid.
        """
        signer_ids = sorted(ps.signer_id for ps in partial_sigs)

        # check authorisation
        if not self.access.is_authorised(set(signer_ids)):
            raise ValueError("signer set does not satisfy access structure")

        # check Pólya conditions
        bk_points = self.access.get_birkhoff_points(signer_ids)
        if not check_polya_conditions(bk_points):
            raise ValueError("signer set violates Pólya conditions")

        binding_data = _compute_binding_data(
            session_id, message, commitments, signer_ids,
        )

        # aggregate nonce
        R = _compute_aggregate_nonce(
            message, binding_data, commitments, signer_ids,
        )

        # Schnorr challenge
        c = hash_sig(R, self.pk, message)

        # Birkhoff coefficients
        lambdas = all_birkhoff_coefficients(signer_ids, bk_points)

        # verify each partial signature individually
        for ps in partial_sigs:
            idx = signer_ids.index(ps.signer_id)
            rho_j = hash_binding(ps.signer_id, message, binding_data)
            D_j = commitments[ps.signer_id].D
            E_j = commitments[ps.signer_id].E

            # Expected R_i = D_j + ρ_j · E_j
            expected_R_i = D_j + (rho_j * E_j)

            # Verify:  z_i · G  ==  R_i  +  c · λ_i · Y_i
            Y_i = self.public_shares[ps.signer_id]
            lhs = ps.z_i * G
            rhs = expected_R_i + (c * lambdas[idx] * Y_i)

            if lhs != rhs:
                raise ValueError(
                    f"invalid partial signature from signer {ps.signer_id}"
                )

        # aggregate: z = Σ z_i
        z = Scalar.zero()
        for ps in partial_sigs:
            z = z + ps.z_i

        sig = ThresholdSignature(R=R, z=z)

        # final verification (sanity check — should always pass if
        # individual checks passed)
        if not verify_signature(self.pk, message, sig):
            raise ValueError(
                "aggregated signature is invalid — this should not happen "
                "if individual partial signatures verified correctly"
            )

        return sig


# ── verification ────────────────────────────────────────────────────────

def verify_signature(
    public_key: Point,
    message: bytes,
    sig: ThresholdSignature,
) -> bool:
    """
    Standard Schnorr verification:  z·G  ==  R + c·Y.

    The signature produced by HABTS is indistinguishable from a single-
    signer Schnorr signature; any standard verifier works.
    """
    c = hash_sig(sig.R, public_key, message)
    lhs = sig.z * G
    rhs = sig.R + (c * public_key)
    return lhs == rhs


# ── helpers ─────────────────────────────────────────────────────────────

def _compute_binding_data(
    session_id: bytes,
    message: bytes,
    commitments: Dict[int, NonceCommitment],
    signer_ids: List[int],
) -> bytes:
    """
    Canonical encoding of session + message + ordered commitments.

    This is the input to the binding-factor hash (FROST §4).
    The inclusion of all commitments in the hash prevents a malicious
    signer from adaptively choosing their nonce after seeing others.
    """
    import hashlib
    h = hashlib.sha256()
    h.update(b"HABTS/v1/binding_data")
    h.update(session_id)
    h.update(message)
    for pid in sorted(signer_ids):
        h.update(commitments[pid].to_bytes())
    return h.digest()


def _compute_aggregate_nonce(
    message: bytes,
    binding_data: bytes,
    commitments: Dict[int, NonceCommitment],
    signer_ids: List[int],
) -> Point:
    """Compute aggregate nonce R = Σ (D_j + ρ_j · E_j)."""
    parts: List[Point] = []
    for pid in signer_ids:
        rho_j = hash_binding(pid, message, binding_data)
        R_j = commitments[pid].D + (rho_j * commitments[pid].E)
        parts.append(R_j)
    return Point.sum_points(parts)
