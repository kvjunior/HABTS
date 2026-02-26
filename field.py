"""
Scalar-field utilities for Z_q  (q = secp256k1 curve order).

Provides batch operations and combinatorial helpers needed by the
Birkhoff interpolation and polynomial modules.  Individual ``Scalar``
arithmetic lives in :pymod:`curve`.
"""

from __future__ import annotations

from typing import List

from .curve import Scalar, ORDER


# ── batch inverse (Montgomery's trick) ──────────────────────────────────
def batch_inverse(scalars: List[Scalar]) -> List[Scalar]:
    """
    Invert a list of non-zero scalars using a single modular
    exponentiation (Montgomery's trick).

    Cost: 3(n-1) multiplications + 1 inversion  vs  n inversions naïvely.

    Raises ``ZeroDivisionError`` if any element is zero.
    """
    n = len(scalars)
    if n == 0:
        return []
    if n == 1:
        return [scalars[0].inv()]

    # prefix products  p[i] = s[0] * s[1] * … * s[i]
    prefix = [Scalar.zero()] * n
    prefix[0] = scalars[0]
    for i in range(1, n):
        prefix[i] = prefix[i - 1] * scalars[i]

    # single inversion of the total product
    inv_all = prefix[-1].inv()

    # back-substitution
    result = [Scalar.zero()] * n
    for i in range(n - 1, 0, -1):
        result[i] = prefix[i - 1] * inv_all
        inv_all = inv_all * scalars[i]
    result[0] = inv_all
    return result


# ── combinatorial helpers in Z_q ────────────────────────────────────────
def factorial_scalar(n: int) -> Scalar:
    """n!  computed in Z_q.  Valid for n < q (always true here)."""
    if n < 0:
        raise ValueError("factorial of negative number")
    r = Scalar.one()
    for i in range(2, n + 1):
        r = r * Scalar(i)
    return r


def binomial_scalar(n: int, k: int) -> Scalar:
    r"""
    Binomial coefficient  C(n, k) = n! / (k! (n-k)!)  in Z_q.

    Used in Birkhoff matrix construction:

    .. math::
        B_{i,j} = \binom{j}{\beta_i} \cdot \alpha_i^{\,j - \beta_i}
    """
    if k < 0 or k > n:
        return Scalar.zero()
    if k == 0 or k == n:
        return Scalar.one()
    # Use symmetry to reduce multiplications
    if k > n - k:
        k = n - k
    num = Scalar.one()
    den = Scalar.one()
    for i in range(k):
        num = num * Scalar(n - i)
        den = den * Scalar(i + 1)
    return num / den


def falling_factorial(n: int, k: int) -> Scalar:
    r"""
    Falling factorial  n^{(k)} = n (n-1) … (n-k+1)  in Z_q.

    Equivalent to  k! · C(n, k).  Appears in derivative evaluation:
    (d^k/dx^k) x^n = n^{(k)} x^{n-k}.
    """
    if k < 0:
        raise ValueError("negative falling factorial order")
    r = Scalar.one()
    for i in range(k):
        r = r * Scalar(n - i)
    return r


# ── linear-algebra helpers ──────────────────────────────────────────────
def solve_linear_system(
    matrix: List[List[Scalar]],
    rhs: List[Scalar],
) -> List[Scalar]:
    """
    Solve  M x = b  in Z_q  via Gaussian elimination with partial
    pivoting.  Returns solution vector *x*.

    Parameters
    ----------
    matrix : n × n list-of-lists of ``Scalar``
        Coefficient matrix (will be copied internally).
    rhs : length-n list of ``Scalar``
        Right-hand side vector (will be copied internally).

    Raises
    ------
    ValueError
        If the system is singular (Birkhoff matrix is degenerate for
        the chosen signer set — check Pólya conditions).
    """
    n = len(rhs)
    if n == 0:
        return []
    if len(matrix) != n or any(len(row) != n for row in matrix):
        raise ValueError(f"expected {n}×{n} matrix, got inconsistent dims")

    # deep copy into augmented matrix
    aug = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]

    for col in range(n):
        # partial pivot: find non-zero entry in column
        pivot = None
        for row in range(col, n):
            if not aug[row][col].is_zero():
                pivot = row
                break
        if pivot is None:
            raise ValueError(
                "singular Birkhoff matrix — signer set may violate "
                "Pólya conditions for the chosen hierarchy"
            )
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]

        inv_diag = aug[col][col].inv()
        for j in range(col, n + 1):
            aug[col][j] = aug[col][j] * inv_diag

        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            if factor.is_zero():
                continue
            for j in range(col, n + 1):
                aug[row][j] = aug[row][j] - factor * aug[col][j]

    return [aug[i][n] for i in range(n)]
