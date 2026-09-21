
import hashlib
import secrets

#  Curve parameters (secp256k1): y^2 = x^3 + a*x + b  (mod p)
P = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
A = 0
B = 7
Gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
Gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
G = (Gx, Gy)
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141  # order of G

# Point at infinity (identity element)
INF = None

def inverse_mod(x, m):
    """Modular inverse via Fermat's little theorem (m must be prime)."""
    return pow(x, m - 2, m)


def point_add(p1, p2):
    """Add two points on the curve. Handles doubling and the identity."""
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return INF  # p1 + (-p1) = point at infinity

    if p1 == p2:
        # Point doubling: slope = (3x^2 + a) / (2y)
        m = (3 * x1 * x1 + A) * inverse_mod(2 * y1, P) % P
    else:
        # Point addition: slope = (y2 - y1) / (x2 - x1)
        m = (y2 - y1) * inverse_mod((x2 - x1) % P, P) % P

    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    """k * point via double-and-add (the EC analogue of fast exponentiation)."""
    result = INF
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def generate_keypair():
    private_key = secrets.randbelow(N - 1) + 1     # d in [1, N-1]
    public_key = scalar_mult(private_key, G)       # Q = d * G
    return private_key, public_key

def hash_message(message: bytes) -> int:
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, "big") % N

def sign(private_key: int, message: bytes, k: int | None = None):
    z = hash_message(message)
    while True:
        nonce = k if k is not None else secrets.randbelow(N - 1) + 1
        x1, _ = scalar_mult(nonce, G)
        r = x1 % N
        if r == 0:
            continue  # bad luck, retry with a fresh nonce
        s = (inverse_mod(nonce, N) * (z + r * private_key)) % N
        if s == 0:
            continue
        return r, s


def verify(public_key, message: bytes, signature) -> bool:
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False

    z = hash_message(message)
    w = inverse_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N

    x1, _ = point_add(scalar_mult(u1, G), scalar_mult(u2, public_key))
    return (x1 % N) == r


def recover_key_from_nonce_reuse(msg1, sig1, msg2, sig2):
    r1, s1 = sig1
    r2, s2 = sig2
    assert r1 == r2, "r must match for this to be a nonce-reuse case"

    z1 = hash_message(msg1)
    z2 = hash_message(msg2)

    # Derivation:
    #   s1 = k^-1 (z1 + r*d)
    #   s2 = k^-1 (z2 + r*d)
    #   => s1 - s2 = k^-1 (z1 - z2)
    #   => k = (z1 - z2) / (s1 - s2)
    k = ((z1 - z2) * inverse_mod((s1 - s2) % N, N)) % N

    # Once k is known, recover d from either signature:
    #   d = (s*k - z) / r
    r = r1
    d = ((s1 * k - z1) * inverse_mod(r, N)) % N
    return d, k


if __name__ == "__main__":
    print("=== Basic sign / verify ===")
    priv, pub = generate_keypair()
    msg = b"transfer 10 BTC to Alice"
    sig = sign(priv, msg)
    print(f"private key : {hex(priv)}")
    print(f"public key  : ({hex(pub[0])}, {hex(pub[1])})")
    print(f"signature   : r={hex(sig[0])}, s={hex(sig[1])}")
    print(f"valid?      : {verify(pub, msg, sig)}")

    tampered = b"transfer 10000 BTC to Alice"
    print(f"tampered msg valid? : {verify(pub, tampered, sig)}")

    print("\n=== Nonce-reuse attack ===")
    fixed_k = secrets.randbelow(N - 1) + 1  # attacker doesn't know this,
                                             # but the *victim* reused it
    msg_a = b"send 1 BTC to Bob"
    msg_b = b"send 5 BTC to Carol"
    sig_a = sign(priv, msg_a, k=fixed_k)
    sig_b = sign(priv, msg_b, k=fixed_k)

    print(f"sig A: r={hex(sig_a[0])}, s={hex(sig_a[1])}")
    print(f"sig B: r={hex(sig_b[0])}, s={hex(sig_b[1])}")
    print("(same r in both -> same k was used -> key is recoverable)")

    recovered_d, recovered_k = recover_key_from_nonce_reuse(msg_a, sig_a, msg_b, sig_b)
    print(f"recovered private key : {hex(recovered_d)}")
    print(f"actual private key    : {hex(priv)}")
    print(f"match? {recovered_d == priv}")