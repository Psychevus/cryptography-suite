from typing import List, Tuple
import secrets

def mod_inverse(a: int, p: int) -> int:
    """
    Computes the modular inverse of a modulo p using extended Euclidean algorithm.
    """
    try:
        return pow(a, -1, p)
    except ValueError as e:
        raise ValueError(f"No modular inverse exists for {a} modulo {p}: {e}")


def lagrange_interpolate(x: int, x_s: List[int], y_s: List[int], p: int) -> int:
    """
    Performs Lagrange interpolation to find the secret.
    """
    total = 0
    n = len(x_s)
    for i in range(n):
        xi, yi = x_s[i], y_s[i]
        li_num = 1
        li_den = 1
        for j in range(n):
            if i != j:
                xj = x_s[j]
                li_num = (li_num * (-xj % p)) % p
                li_den = (li_den * (xi - xj)) % p
        li = yi * li_num * mod_inverse(li_den, p)
        total = (total + li) % p
    return total


def create_shares(secret: int, threshold: int, num_shares: int, prime: int = 2**521 - 1) -> List[Tuple[int, int]]:
    """
    Splits a secret into shares using Shamir's Secret Sharing.
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot be greater than the number of shares.")
    if secret >= prime:
        raise ValueError("Secret must be less than the prime number.")

    # Generate random coefficients for the polynomial
    coeffs = [secret] + [secrets.randbelow(prime) for _ in range(threshold - 1)]

    shares = []
    for i in range(1, num_shares + 1):
        x = i
        y = sum([coeffs[j] * pow(x, j, prime) for j in range(len(coeffs))]) % prime
        shares.append((x, y))
    return shares


def reconstruct_secret(shares: List[Tuple[int, int]], prime: int = 2**521 - 1) -> int:
    """
    Reconstructs the secret from shares using Lagrange interpolation.
    """
    x_s, y_s = zip(*shares)
    secret = lagrange_interpolate(0, list(x_s), list(y_s), prime)
    return secret
