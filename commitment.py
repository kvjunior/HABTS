"""
Pedersen commitment scheme and polynomial commitments.

A Pedersen commitment to *m* with randomness *r* is:

    C = m·G + r·H

where G and H are independent generators with unknown discrete-log
relation (H is derived via NUMS hash-to-curve; see curve.py).

Security:
- Perfectly hiding — C reveals no information about *m*.
- Computationally binding — finding (m', r') ≠ (m, r) with the same C
  requires solving the discrete-log problem for log_G(H).

Used in:
1. DKG verification — commit to polynomial coefficients.
2. Accountability proofs — commit to signer participation.

References
----------
- Pedersen (1991). "Non-Interactive and Information-Theoretic Secure
  Verifiable Secret Sharing."  CRYPTO 1991.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .curve import Scalar, Point, G, H


@dataclass(frozen=True)
class PedersenCommitment:
    """A single Pedersen commitment  C = m·G + r·H."""

    point: Point

    @staticmethod
    def commit(value: Scalar, randomness: Scalar) -> PedersenCommitment:
        """Commit(m, r) → C = m·G + r·H."""
        C = (value * G) + (randomness * H)
        return PedersenCommitment(point=C)

    def verify(self, value: Scalar, randomness: Scalar) -> bool:
        """Verify that this commitment opens to (value, randomness)."""
        expected = (value * G) + (randomness * H)
        return self.point == expected

    def to_bytes(self) -> bytes:
        return self.point.to_bytes_compressed()

    @classmethod
    def from_bytes(cls, data: bytes) -> PedersenCommitment:
        return cls(point=Point.from_bytes(data))


@dataclass
class PolynomialCommitment:
    """
    Pedersen commitment to an entire polynomial.

    For polynomial  f(x) = a_0 + a_1 x + … + a_d x^d  with blinding
    polynomial  f̃(x) = r_0 + r_1 x + … + r_d x^d, the commitments are:

        C_j = a_j·G + r_j·H   for  j = 0, …, d

    Share verification:  for share  s_i = f(α_i), blinding  s̃_i = f̃(α_i),
    check that  s_i·G + s̃_i·H  ==  Σ_j C_j · α_i^j.
    """

    commitments: List[PedersenCommitment]

    @staticmethod
    def commit_polynomial(
        coeffs: List[Scalar],
        blinding_coeffs: List[Scalar],
    ) -> PolynomialCommitment:
        """
        Commit to polynomial coefficients with blinding.

        Parameters
        ----------
        coeffs : list[Scalar]
            Polynomial coefficients [a_0, …, a_d].
        blinding_coeffs : list[Scalar]
            Blinding coefficients [r_0, …, r_d] (same length).
        """
        if len(coeffs) != len(blinding_coeffs):
            raise ValueError("coefficient lists must have equal length")
        comms = [
            PedersenCommitment.commit(a, r)
            for a, r in zip(coeffs, blinding_coeffs)
        ]
        return PolynomialCommitment(commitments=comms)

    def verify_share(
        self,
        eval_point: int,
        share_value: Scalar,
        blinding_value: Scalar,
    ) -> bool:
        """
        Verify that share (s, s̃) is consistent with the committed
        polynomial at evaluation point α (derivative order 0).

        Check:  s·G + s̃·H  ==  Σ_j C_j · α^j
        """
        lhs = (share_value * G) + (blinding_value * H)

        alpha = Scalar(eval_point)
        rhs = Point.identity()
        alpha_pow = Scalar.one()
        for c in self.commitments:
            rhs = rhs + (alpha_pow * c.point)
            alpha_pow = alpha_pow * alpha

        return lhs == rhs

    def verify_derivative_share(
        self,
        eval_point: int,
        derivative_order: int,
        share_value: Scalar,
        blinding_value: Scalar,
    ) -> bool:
        r"""
        Verify a Birkhoff derivative share against polynomial commitment.

        For derivative order β at point α, the committed value should be:

            f^{(β)}(α)/β! = Σ_{j≥β} C(j,β) · a_j · α^{j−β}

        and the corresponding Pedersen structure:

            LHS = share·G + blinding·H
            RHS = Σ_{j≥β} C(j,β) · α^{j−β} · C_j

        This verifies both the secret share and blinding share
        simultaneously thanks to the homomorphic property of Pedersen
        commitments.
        """
        if derivative_order == 0:
            return self.verify_share(eval_point, share_value, blinding_value)

        from .field import binomial_scalar

        lhs = (share_value * G) + (blinding_value * H)

        alpha = Scalar(eval_point)
        rhs = Point.identity()
        for j, c in enumerate(self.commitments):
            if j < derivative_order:
                continue
            binom = binomial_scalar(j, derivative_order)
            power = alpha ** (j - derivative_order)
            factor = binom * power
            rhs = rhs + (factor * c.point)

        return lhs == rhs

    @property
    def degree(self) -> int:
        return len(self.commitments) - 1

    @property
    def constant_commitment(self) -> PedersenCommitment:
        """Commitment to a_0 (the secret)."""
        return self.commitments[0]

    def to_bytes(self) -> bytes:
        parts = [len(self.commitments).to_bytes(4, "big")]
        for c in self.commitments:
            parts.append(c.to_bytes())
        return b"".join(parts)
