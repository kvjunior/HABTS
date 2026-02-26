"""
Polynomial arithmetic and Birkhoff interpolation over Z_q.

Standard Lagrange interpolation reconstructs f(0) from point-value
pairs {(α_i, f(α_i))}.  Birkhoff interpolation generalises this to
mixed conditions involving derivatives:

    {(α_i, β_i, v_i)}  where  v_i = f^{(β_i)}(α_i) / β_i!

This enables hierarchical secret sharing [Tassa, J. Cryptology 2007]:
higher-authority participants receive lower-order derivative shares,
requiring fewer of them to reconstruct the secret.

References
----------
- Tassa (2007). "Hierarchical Threshold Secret Sharing."
  Journal of Cryptology 20(2), pp. 237-264.
- Schoenberg (1966). "On Hermite-Birkhoff Interpolation."
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .curve import Scalar, Point, G
from .field import (
    batch_inverse, binomial_scalar, falling_factorial,
    factorial_scalar, solve_linear_system,
)


# ── polynomial representation ───────────────────────────────────────────
#  coefficients[i] = a_i   so  f(x) = a_0 + a_1 x + a_2 x^2 + …


def sample_polynomial(
    degree: int,
    constant: Optional[Scalar] = None,
) -> List[Scalar]:
    """
    Sample a uniformly random polynomial of the given degree.

    Parameters
    ----------
    degree : int  (≥ 0)
        Polynomial degree  d;  result has  d+1  coefficients.
    constant : Scalar or None
        If given, force a_0 = constant (used to share a secret).
    """
    if degree < 0:
        raise ValueError("degree must be ≥ 0")
    a0 = constant if constant is not None else Scalar.random()
    return [a0] + [Scalar.random() for _ in range(degree)]


def evaluate(coeffs: List[Scalar], x: Scalar) -> Scalar:
    """Evaluate f(x) via Horner's method — O(d) mults."""
    if not coeffs:
        return Scalar.zero()
    result = coeffs[-1]
    for c in reversed(coeffs[:-1]):
        result = result * x + c
    return result


def evaluate_derivative(
    coeffs: List[Scalar],
    x: Scalar,
    order: int,
) -> Scalar:
    r"""
    Evaluate the *order*-th derivative of *f* at *x*  (**divided** by
    order! — the Birkhoff convention).

    .. math::
        \frac{f^{(k)}(x)}{k!}
        = \sum_{j \ge k} \binom{j}{k}\, a_j\, x^{j-k}

    This "normalised derivative" avoids large factorials and matches
    Tassa's share definition directly.
    """
    if order < 0:
        raise ValueError("derivative order must be ≥ 0")
    if order == 0:
        return evaluate(coeffs, x)

    d = len(coeffs) - 1          # polynomial degree
    if order > d:
        return Scalar.zero()

    # Build reduced coefficients  b_j = C(j+order, order) * a_{j+order}
    reduced: List[Scalar] = []
    for j in range(d - order + 1):
        reduced.append(binomial_scalar(j + order, order) * coeffs[j + order])

    return evaluate(reduced, x)


# ── Birkhoff matrix and coefficient computation ─────────────────────────

BirkhoffPoint = Tuple[int, int]    # (α_i, β_i) evaluation point + deriv order


def check_polya_conditions(points: List[BirkhoffPoint]) -> bool:
    r"""
    Check the Pólya conditions for a set of Birkhoff interpolation
    points.

    The Pólya necessary condition states: for each k = 0, …, n-1,
    the number of points with derivative order ≤ k must be > k.
    Equivalently, when sorting by derivative order, position i must
    have β_i ≤ i.

    This is necessary (but not always sufficient) for the Birkhoff
    matrix to be non-singular.  For hierarchical threshold schemes
    with distinct α_i, it is also sufficient [Tassa 2007].

    Parameters
    ----------
    points : list of (alpha, beta) pairs
        The Birkhoff interpolation points for the signer set.

    Returns
    -------
    bool
        True if the Pólya conditions are satisfied.
    """
    n = len(points)
    if n == 0:
        return True

    # Sort by derivative order
    sorted_betas = sorted(beta for _, beta in points)

    # Pólya condition: for each position i, beta[i] ≤ i
    for i, beta in enumerate(sorted_betas):
        if beta > i:
            return False
    return True


def birkhoff_matrix(
    points: List[BirkhoffPoint],
) -> List[List[Scalar]]:
    r"""
    Construct the Birkhoff interpolation matrix B.

    For reconstruction of  f(0)  from  {(α_i, β_i, share_i)}  we need:

    .. math::
        B_{i,j} = \binom{j}{\beta_i} \cdot \alpha_i^{\,j - \beta_i}
        \qquad (j \ge \beta_i,\; \text{else } 0)

    The matrix is  n × n  where  n = len(points) = degree + 1.
    """
    n = len(points)
    mat: List[List[Scalar]] = []
    for alpha_int, beta in points:
        alpha = Scalar(alpha_int)
        row: List[Scalar] = []
        for j in range(n):
            if j < beta:
                row.append(Scalar.zero())
            else:
                coeff = binomial_scalar(j, beta)
                power = alpha ** (j - beta)
                row.append(coeff * power)
        mat.append(row)
    return mat


def birkhoff_coefficients(
    target_signer: int,
    signer_ids: List[int],
    points: List[BirkhoffPoint],
) -> Scalar:
    r"""
    Compute the Birkhoff coefficient  λ_i  for ``target_signer`` such
    that:

    .. math::
        f(0) = \sum_{j \in S} \lambda_j \cdot
               \frac{f^{(\beta_j)}(\alpha_j)}{\beta_j!}

    This is the core calculation that replaces Lagrange coefficients in
    FROST.  We solve the Birkhoff matrix system and extract the column
    corresponding to the constant term.

    Parameters
    ----------
    target_signer : int
        Participant ID whose coefficient to compute.
    signer_ids : list[int]
        All participating signer IDs (defines the set *S*).
    points : list[(alpha, beta)]
        Birkhoff points for each signer in *signer_ids* (same order).
    """
    n = len(signer_ids)
    if n != len(points):
        raise ValueError("signer_ids and points must have equal length")
    if target_signer not in signer_ids:
        raise ValueError(f"target_signer {target_signer} not in signer_ids")

    if not check_polya_conditions(points):
        raise ValueError("signer set violates Pólya conditions")

    idx = signer_ids.index(target_signer)
    lambdas = all_birkhoff_coefficients(signer_ids, points)
    return lambdas[idx]


def all_birkhoff_coefficients(
    signer_ids: List[int],
    points: List[BirkhoffPoint],
) -> List[Scalar]:
    r"""
    Return the Birkhoff coefficient for every signer in one solve.

    We want  λ_j = B^{-1}[0, j]  (first row of the inverse).
    This is obtained by solving  B^T · c = e_0  where e_0 is the
    first standard basis vector, giving  c_j = (B^{-1})^T[j, 0]
    = B^{-1}[0, j] = λ_j.
    """
    n = len(signer_ids)
    if n == 0:
        return []
    if n != len(points):
        raise ValueError("signer_ids and points must have equal length")

    B = birkhoff_matrix(points)

    # Transpose B
    BT = [[B[r][c] for r in range(n)] for c in range(n)]
    e0 = [Scalar.one() if i == 0 else Scalar.zero() for i in range(n)]
    return solve_linear_system(BT, e0)


# ── Lagrange coefficients (for comparison / fallback) ───────────────────

def lagrange_coefficient(
    target_id: int,
    signer_ids: List[int],
) -> Scalar:
    r"""
    Standard Lagrange coefficient for participant *target_id* in set *S*:

    .. math::
        \lambda_i = \prod_{j \in S,\; j \ne i}
            \frac{j}{j - i}
    """
    if target_id not in signer_ids:
        raise ValueError(f"target_id {target_id} not in signer_ids")
    xi = Scalar(target_id)
    num = Scalar.one()
    den = Scalar.one()
    for sid in signer_ids:
        if sid == target_id:
            continue
        xj = Scalar(sid)
        num = num * xj
        den = den * (xj - xi)
    return num / den


# ── polynomial commitment (Feldman-style) ───────────────────────────────

def commit_polynomial(coeffs: List[Scalar]) -> List[Point]:
    """
    Feldman commitment:  C_j = a_j · G  for each coefficient.

    Allows verification of shares without revealing the polynomial.
    """
    return [c * G for c in coeffs]


def verify_share_feldman(
    share: Scalar,
    eval_point: int,
    commitments: List[Point],
) -> bool:
    """
    Verify that ``share`` is consistent with the Feldman commitments.

    Check:  share · G  ==  Σ_j  C_j · (eval_point)^j
    """
    lhs = share * G
    x = Scalar(eval_point)
    rhs = Point.identity()
    x_pow = Scalar.one()
    for C_j in commitments:
        rhs = rhs + (x_pow * C_j)
        x_pow = x_pow * x
    return lhs == rhs
