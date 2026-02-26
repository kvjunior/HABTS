"""
Elliptic curve arithmetic on secp256k1 via libsecp256k1.

Every expensive group operation (scalar multiplication, point addition)
is delegated to the C library ``coincurve``, which wraps Bitcoin Core's
libsecp256k1.  This gives ~0.04 ms per scalar-mult vs ~55 ms in pure
Python — a factor critical for credible benchmarks.

Install
-------
    pip install coincurve>=18.0.0

References
----------
- SEC 2 v2 §2.4.1  secp256k1 domain parameters
- BIP-340            Schnorr signature specification for Bitcoin
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Optional, List

from coincurve import PrivateKey as _SK, PublicKey as _PK

# ── secp256k1 constants ─────────────────────────────────────────────────
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SCALAR_BYTES = 32
COMPRESSED_BYTES = 33


# ── Scalar  (Z_q arithmetic, pure Python — field ops are fast) ──────────
class Scalar:
    """Element of the scalar field  Z_q  where *q* = ``ORDER``."""

    __slots__ = ("_v",)

    def __init__(self, value: int) -> None:
        self._v = value % ORDER

    # constructors -----------------------------------------------------------
    @classmethod
    def zero(cls) -> Scalar:
        return cls(0)

    @classmethod
    def one(cls) -> Scalar:
        return cls(1)

    @classmethod
    def random(cls) -> Scalar:
        """Uniform in [1, q-1] via rejection sampling."""
        while True:
            c = int.from_bytes(secrets.token_bytes(SCALAR_BYTES), "big")
            if 0 < c < ORDER:
                return cls(c)

    @classmethod
    def from_bytes(cls, data: bytes) -> Scalar:
        if len(data) != SCALAR_BYTES:
            raise ValueError(f"need {SCALAR_BYTES} bytes, got {len(data)}")
        v = int.from_bytes(data, "big")
        if v >= ORDER:
            raise ValueError("scalar out of range")
        return cls(v)

    @classmethod
    def from_bytes_reduce(cls, data: bytes) -> Scalar:
        """Hash-output safe: reduce arbitrary length modulo *q*."""
        return cls(int.from_bytes(data, "big"))

    # serialisation ----------------------------------------------------------
    def to_bytes(self) -> bytes:
        return self._v.to_bytes(SCALAR_BYTES, "big")

    @property
    def value(self) -> int:
        return self._v

    def is_zero(self) -> bool:
        return self._v == 0

    # arithmetic -------------------------------------------------------------
    def __add__(self, o: Scalar) -> Scalar:
        if not isinstance(o, Scalar):
            return NotImplemented
        return Scalar((self._v + o._v) % ORDER)

    def __radd__(self, o):
        if isinstance(o, int) and o == 0:
            return self                       # for sum()
        return NotImplemented

    def __sub__(self, o: Scalar) -> Scalar:
        if not isinstance(o, Scalar):
            return NotImplemented
        return Scalar((self._v - o._v) % ORDER)

    def __mul__(self, o):
        if isinstance(o, Scalar):
            return Scalar((self._v * o._v) % ORDER)
        if isinstance(o, Point):
            return o._smul(self)
        return NotImplemented

    def __rmul__(self, o):
        if isinstance(o, int):
            return Scalar((o * self._v) % ORDER)
        return NotImplemented

    def __neg__(self) -> Scalar:
        return Scalar((-self._v) % ORDER)

    def __truediv__(self, o: Scalar) -> Scalar:
        if not isinstance(o, Scalar):
            return NotImplemented
        return self * o.inv()

    def __pow__(self, e: int) -> Scalar:
        if e < 0:
            return self.inv() ** (-e)
        return Scalar(pow(self._v, e, ORDER))

    def inv(self) -> Scalar:
        """Multiplicative inverse via Fermat's little theorem."""
        if self._v == 0:
            raise ZeroDivisionError("cannot invert zero scalar")
        return Scalar(pow(self._v, ORDER - 2, ORDER))

    # comparison / hashing ---------------------------------------------------
    def __eq__(self, o: object) -> bool:
        if isinstance(o, Scalar):
            return self._v == o._v
        if isinstance(o, int):
            return self._v == o % ORDER
        return False

    def __hash__(self) -> int:
        return hash(self._v)

    def __bool__(self) -> bool:
        return self._v != 0

    def __repr__(self) -> str:
        h = hex(self._v)
        return f"Scalar(0x{h[2:10]}…)" if len(h) > 14 else f"Scalar({h})"


# ── Point  (secp256k1 group element via libsecp256k1) ───────────────────
class Point:
    """
    Point on secp256k1.

    The identity (point at infinity) is represented by a flag rather than
    a ``coincurve.PublicKey``; this matches the algebraic convention
    *P + O = P* and avoids library quirks around serialising the identity.
    """

    __slots__ = ("_pk", "_inf")

    def __init__(self, *, pk: Optional[_PK] = None, infinity: bool = False):
        self._pk: Optional[_PK] = pk
        self._inf: bool = infinity

    # constructors -----------------------------------------------------------
    @classmethod
    def generator(cls) -> Point:
        """Standard base point *G*."""
        return cls(pk=_SK(b"\x00" * 31 + b"\x01").public_key)

    @classmethod
    def generator_h(cls) -> Point:
        """
        Second generator *H* for Pedersen commitments.

        Derived via try-and-increment hash-to-curve (NUMS — Nothing Up
        My Sleeve) so that log_G(H) is **unknown**.  This is essential
        for the computational binding property of Pedersen commitments.

        Method: hash a counter to obtain a candidate x-coordinate,
        check whether x³ + 7 has a square root mod p, and if so
        construct the point with even y-coordinate.  The resulting
        point has no known discrete-log relationship to G.
        """
        prefix = b"HABTS/NUMS/generator_H/secp256k1/v1"
        for counter in range(256):
            data = prefix + counter.to_bytes(4, "big")
            x_bytes = hashlib.sha256(data).digest()
            x_int = int.from_bytes(x_bytes, "big")
            if x_int == 0 or x_int >= FIELD_PRIME:
                continue
            # Check if x³ + 7 is a quadratic residue mod p
            y_sq = (pow(x_int, 3, FIELD_PRIME) + 7) % FIELD_PRIME
            # Euler criterion: y_sq^{(p-1)/2} == 1 mod p iff QR
            if pow(y_sq, (FIELD_PRIME - 1) // 2, FIELD_PRIME) != 1:
                continue
            # Compute y = y_sq^{(p+1)/4} mod p  (valid since p ≡ 3 mod 4)
            y_int = pow(y_sq, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
            # Choose even y
            if y_int % 2 != 0:
                y_int = FIELD_PRIME - y_int
            # Construct compressed encoding: 0x02 prefix + x
            x_bytes_padded = x_int.to_bytes(32, "big")
            compressed = b"\x02" + x_bytes_padded
            try:
                pk = _PK(compressed)
                return cls(pk=pk)
            except Exception:
                continue
        raise RuntimeError("failed to derive NUMS generator H")

    @classmethod
    def identity(cls) -> Point:
        """Point at infinity — additive identity."""
        return cls(infinity=True)

    @classmethod
    def from_scalar(cls, s: Scalar) -> Point:
        """Compute *s · G*."""
        if s.is_zero():
            return cls.identity()
        return cls(pk=_SK(s.to_bytes()).public_key)

    @classmethod
    def from_bytes(cls, data: bytes) -> Point:
        """Deserialise SEC 1 compressed (33 B) or uncompressed (65 B)."""
        if all(b == 0 for b in data):
            return cls.identity()
        return cls(pk=_PK(data))

    # serialisation ----------------------------------------------------------
    def to_bytes_compressed(self) -> bytes:
        if self._inf:
            return b"\x00" * COMPRESSED_BYTES
        return self._pk.format(compressed=True)  # type: ignore[union-attr]

    def to_bytes(self) -> bytes:
        return self.to_bytes_compressed()

    @property
    def x(self) -> int:
        if self._inf:
            return 0
        raw = self._pk.format(compressed=False)  # type: ignore[union-attr]
        return int.from_bytes(raw[1:33], "big")

    @property
    def y(self) -> int:
        if self._inf:
            return 0
        raw = self._pk.format(compressed=False)  # type: ignore[union-attr]
        return int.from_bytes(raw[33:65], "big")

    def is_inf(self) -> bool:
        return self._inf

    # group operations -------------------------------------------------------
    def _smul(self, s: Scalar) -> Point:
        """Scalar multiplication  s · self  (C speed)."""
        if self._inf or s.is_zero():
            return Point.identity()
        copy = _PK(self._pk.format())  # type: ignore[union-attr]
        return Point(pk=copy.multiply(s.to_bytes()))

    def __neg__(self) -> Point:
        if self._inf:
            return self
        raw = bytearray(self._pk.format(compressed=True))  # type: ignore
        raw[0] ^= 0x01            # 0x02 ↔ 0x03 flip parity
        return Point(pk=_PK(bytes(raw)))

    def __add__(self, o: Point) -> Point:
        if not isinstance(o, Point):
            return NotImplemented
        if self._inf:
            return o
        if o._inf:
            return self
        # check for P + (-P) = O
        if self._pk.format() == (-o)._pk.format():  # type: ignore
            return Point.identity()
        return Point(pk=_PK.combine_keys(
            [self._pk, o._pk]))  # type: ignore[list-item]

    def __sub__(self, o: Point) -> Point:
        return self + (-o)

    def __rmul__(self, s) -> Point:
        if isinstance(s, Scalar):
            return self._smul(s)
        if isinstance(s, int):
            return self._smul(Scalar(s))
        return NotImplemented

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, Point):
            return False
        if self._inf and o._inf:
            return True
        if self._inf or o._inf:
            return False
        return self._pk.format() == o._pk.format()  # type: ignore

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def __repr__(self) -> str:
        if self._inf:
            return "Point(∞)"
        return f"Point(0x{self.x:064x})"[:42] + "…)"

    # utility ----------------------------------------------------------------
    @staticmethod
    def sum_points(points: List[Point]) -> Point:
        """Efficient multi-point addition (single libsecp256k1 call)."""
        real = [p for p in points if not p._inf]
        if not real:
            return Point.identity()
        if len(real) == 1:
            return real[0]
        return Point(pk=_PK.combine_keys(
            [p._pk for p in real]))  # type: ignore[list-item]


# ── module-level generators ─────────────────────────────────────────────
G = Point.generator()
H = Point.generator_h()
