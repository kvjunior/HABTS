"""
Zero-knowledge proofs used in the HABTS protocol.

1. **Schnorr Proof of Knowledge** — proves knowledge of discrete log
   x  such that  Y = x·G  without revealing x.  Used in DKG to prove
   each participant knows their secret polynomial's constant term.

2. **DLEQ Proof** — proves that two points share the same discrete-log
   ratio:  log_G(Y) = log_H(Z).  Used in accountability proofs and
   share verification.

Both are made non-interactive via Fiat-Shamir in the Random Oracle
Model.

References
----------
- Schnorr (1989). "Efficient Identification and Signatures for Smart
  Cards."  CRYPTO 1989.
- Chaum & Pedersen (1992). "Wallet Databases with Observers."
  CRYPTO 1992.
"""

from __future__ import annotations

from dataclasses import dataclass

from .curve import Scalar, Point, G
from .hash import hash_schnorr_proof, hash_dleq


# ── Schnorr Proof of Knowledge ──────────────────────────────────────────

@dataclass(frozen=True)
class SchnorrProof:
    """
    Non-interactive proof of knowledge of  x  such that  Y = x·G.

    Transcript: (R, z)  where  R = k·G,  z = k + c·x,  c = H(R, Y, ctx).
    Verification:  z·G  ==  R + c·Y.
    """

    R: Point
    z: Scalar

    @staticmethod
    def prove(
        secret: Scalar,
        public: Point,
        context: bytes = b"",
    ) -> SchnorrProof:
        """
        Produce a Schnorr PoK for  (secret, public = secret·G).

        Parameters
        ----------
        secret : Scalar
            The witness *x*.
        public : Point
            The statement *Y = x·G* (must be consistent).
        context : bytes
            Domain-separation context (e.g., DKG round identifier).
        """
        k = Scalar.random()
        R = k * G
        c = hash_schnorr_proof(R, public, context)
        z = k + c * secret
        return SchnorrProof(R=R, z=z)

    def verify(self, public: Point, context: bytes = b"") -> bool:
        """
        Verify this proof against statement  Y = public.

        Check:  z·G  ==  R + c·Y.
        """
        c = hash_schnorr_proof(self.R, public, context)
        lhs = self.z * G
        rhs = self.R + (c * public)
        return lhs == rhs

    def to_bytes(self) -> bytes:
        return self.R.to_bytes_compressed() + self.z.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> SchnorrProof:
        R = Point.from_bytes(data[:33])
        z = Scalar.from_bytes(data[33:65])
        return cls(R=R, z=z)


# ── DLEQ (Discrete-Log Equality) Proof ─────────────────────────────────

@dataclass(frozen=True)
class DLEQProof:
    """
    Proves  log_G(Y) = log_H(Z)  without revealing the common scalar.

    Given:   Y = x·G,   Z = x·H
    Prove:   same x in both.

    Protocol (Fiat-Shamir):
        k ←$ Z_q
        A1 = k·G,   A2 = k·H
        c  = H(A1, Y, A2, Z, ctx)
        z  = k + c·x

    Verify:
        z·G  ==  A1 + c·Y
        z·H  ==  A2 + c·Z
    """

    A1: Point
    A2: Point
    z: Scalar

    @staticmethod
    def prove(
        secret: Scalar,
        G_base: Point,
        Y: Point,
        H_base: Point,
        Z: Point,
        context: bytes = b"",
    ) -> DLEQProof:
        """
        Prove that  Y = secret·G_base  and  Z = secret·H_base.
        """
        k = Scalar.random()
        A1 = k * G_base
        A2 = k * H_base
        c = hash_dleq(A1, Y, A2, Z, context)
        z = k + c * secret
        return DLEQProof(A1=A1, A2=A2, z=z)

    def verify(
        self,
        G_base: Point,
        Y: Point,
        H_base: Point,
        Z: Point,
        context: bytes = b"",
    ) -> bool:
        """
        Verify the DLEQ proof.

        Check:
            z · G_base == A1 + c · Y
            z · H_base == A2 + c · Z
        """
        c = hash_dleq(self.A1, Y, self.A2, Z, context)

        lhs1 = self.z * G_base
        rhs1 = self.A1 + (c * Y)

        lhs2 = self.z * H_base
        rhs2 = self.A2 + (c * Z)

        return (lhs1 == rhs1) and (lhs2 == rhs2)

    def to_bytes(self) -> bytes:
        return (
            self.A1.to_bytes_compressed()
            + self.A2.to_bytes_compressed()
            + self.z.to_bytes()
        )
