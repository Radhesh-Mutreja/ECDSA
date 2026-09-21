# ECDSA From Scratch — secp256k1 & Nonce-Reuse Attack

A from-scratch Python implementation of **ECDSA (Elliptic Curve Digital Signature Algorithm)** over the **secp256k1** elliptic curve.

The project implements elliptic-curve arithmetic, key generation, message signing, signature verification, and a practical demonstration of the classic **ECDSA nonce-reuse private-key recovery attack**.

> ⚠️ **Educational project only.**
>
> This implementation is intentionally written for learning and experimentation. It has not been audited and should **not** be used for real cryptographic applications, wallets, authentication systems, or production software. Use a vetted cryptographic library such as `cryptography` for real-world applications.

---

## What This Project Demonstrates

The project walks through the core mechanics behind ECDSA without using a cryptographic library for the actual EC/ECDSA operations.

It covers:

* Finite-field arithmetic
* Elliptic-curve point addition
* Elliptic-curve point doubling
* Scalar multiplication using double-and-add
* secp256k1 curve parameters
* Private/public key generation
* SHA-256 message hashing
* ECDSA signing
* ECDSA signature verification
* ECDSA nonce (`k`) reuse
* Private-key recovery from two signatures sharing the same nonce

The final demonstration intentionally reuses the same nonce for two different messages and shows that the private key can then be recovered mathematically.

---

## Requirements

* Python 3.10+
* No external cryptography libraries required

The implementation only uses Python's standard library:

```python
import hashlib
import secrets
```

---

## Running the Project

Save the implementation as:

```text
ecdsa_from_scratch.py
```

Then run:

```bash
python ecdsa_from_scratch.py
```

The program will perform two demonstrations.

### 1. Basic ECDSA

It will:

1. Generate a private key.
2. Derive the corresponding public key.
3. Sign a message.
4. Verify the signature.
5. Modify the message.
6. Demonstrate that the original signature no longer verifies.

Example:

```text
=== Basic sign / verify ===
private key : 0x...
public key  : (0x..., 0x...)
signature   : r=0x..., s=0x...
valid?      : True
tampered msg valid? : False
```

---

# How ECDSA Works

ECDSA relies on elliptic-curve arithmetic over a finite field.

This implementation uses **secp256k1**, the curve historically associated with Bitcoin and also used in Ethereum-related cryptography.

The curve equation is:

$$
y^2 = x^3 + ax + b \pmod p
$$

For secp256k1:

```text
a = 0
b = 7
```

Therefore:

$$
y^2 = x^3 + 7 \pmod p
$$

The curve also defines a generator point:

$$
G = (G_x, G_y)
$$

and a large prime order:

$$
n
$$

---

## 1. Elliptic-Curve Point Addition

The `point_add()` function implements the group operation used by ECDSA.

Given two points:

$$
P_1=(x_1,y_1)
$$

and

$$
P_2=(x_2,y_2)
$$

the implementation calculates the slope and derives the resulting point.

For different points:

$$
m = \frac{y_2-y_1}{x_2-x_1}
$$

For point doubling:

$$
m = \frac{3x_1^2+a}{2y_1}
$$

Division is performed using a modular inverse.

The resulting point is:

$$
x_3=m^2-x_1-x_2
$$

$$
y_3=m(x_1-x_3)-y_1
$$

All operations are performed modulo `P`.

---

## 2. Modular Inverse

The implementation uses Fermat's Little Theorem:

$$
x^{-1}\equiv x^{p-2}\pmod p
$$

This is implemented with Python's built-in modular exponentiation:

```python
pow(x, m - 2, m)
```

This works because the modulus used for the field operations is prime.

---

# Scalar Multiplication

ECDSA repeatedly needs to calculate:

$$
kG
$$

where `k` is a large integer and `G` is the generator point.

The `scalar_mult()` function uses the **double-and-add algorithm**.

Conceptually, this is similar to fast exponentiation.

Instead of adding `G` to itself `k` times, the algorithm repeatedly doubles points and selectively adds them based on the binary representation of `k`.

This reduces the number of required operations from roughly:

$$
O(k)
$$

to:

$$
O(\log k)
$$

---

# Key Generation

A private key is generated as a random integer:

$$
1 \leq d < n
$$

The public key is then calculated:

$$
Q=dG
$$

In code:

```python
private_key = secrets.randbelow(N - 1) + 1
public_key = scalar_mult(private_key, G)
```

The important relationship is:

```text
Private key → Public key
     d      →    dG
```

Calculating the public key from the private key is easy.

Recovering the private key from the public key is intended to be computationally infeasible because of the **elliptic-curve discrete logarithm problem**.

---

# ECDSA Signing

For a message `m`, the implementation first computes:

$$
z = SHA256(m)
$$

converted into an integer modulo `n`.

A secret random nonce `k` is then selected.

The signer calculates:

$$
R=kG
$$

and extracts:

$$
r=R_x\bmod n
$$

The second signature component is:

$$
s=k^{-1}(z+rd)\bmod n
$$

where:

* `d` = private key
* `k` = secret nonce
* `z` = message hash
* `r, s` = signature

The final signature is:

$$
(r,s)
$$

---

# Signature Verification

Given:

* public key `Q`
* message `m`
* signature `(r,s)`

the verifier calculates:

$$
w=s^{-1}\bmod n
$$

Then:

$$
u_1=zw\bmod n
$$

$$
u_2=rw\bmod n
$$

and calculates:

$$
X=u_1G+u_2Q
$$

The signature is valid when:

$$
X_x\bmod n=r
$$

This is what the `verify()` function implements.

---

# Why Nonce Reuse Is Catastrophic

This is the most important part of the project.

Every ECDSA signature must use a **unique, unpredictable nonce** `k`.

Suppose the same private key `d` signs two different messages using the same nonce:

$$
s_1=k^{-1}(z_1+rd)
$$

$$
s_2=k^{-1}(z_2+rd)
$$

Because the same `k` is used, both signatures have the same:

$$
r
$$

Subtracting the two equations gives:

$$
s_1-s_2=k^{-1}(z_1-z_2)
$$

Therefore:

$$
k=\frac{z_1-z_2}{s_1-s_2}\pmod n
$$

Once `k` is recovered, the private key can be calculated:

$$
d=\frac{s_1k-z_1}{r}\pmod n
$$

So the attack becomes:

```text
Two signatures
      ↓
Same r detected
      ↓
Recover k
      ↓
Recover private key d
```

No brute force is required.

---

# Demonstrating the Attack

The demo deliberately creates a reused nonce:

```python
fixed_k = secrets.randbelow(N - 1) + 1

sig_a = sign(priv, msg_a, k=fixed_k)
sig_b = sign(priv, msg_b, k=fixed_k)
```

The two messages are different:

```text
send 1 BTC to Bob
send 5 BTC to Carol
```

But the same `k` is used.

As a result:

```text
sig A → r = X, s = A
sig B → r = X, s = B
```

The matching `r` reveals that the same ephemeral point `kG` was used.

The recovery function then calculates:

```python
recovered_d, recovered_k = recover_key_from_nonce_reuse(
    msg_a,
    sig_a,
    msg_b,
    sig_b
)
```

Finally, it compares the recovered key with the original:

```text
recovered private key : 0x...
actual private key    : 0x...
match? True
```

This demonstrates that a nonce-reuse failure can completely compromise an ECDSA private key.

---

# Attack Flow

```text
              ECDSA Signing
                   │
          ┌────────┴────────┐
          │                 │
       Message A          Message B
          │                 │
         z₁                z₂
          │                 │
          └───────┬─────────┘
                  │
             SAME nonce k
                  │
          ┌───────┴────────┐
          │                 │
       Signature A       Signature B
        (r, s₁)           (r, s₂)
          │                 │
          └───────┬─────────┘
                  │
             Same r detected
                  │
                  ▼
       k = (z₁-z₂)/(s₁-s₂)
                  │
                  ▼
       d = (s₁k-z₁)/r
                  │
                  ▼
          PRIVATE KEY RECOVERED
```

---

# Historical Relevance

Nonce failures are not merely theoretical.

A famous example is the **Sony PlayStation 3 signing-key failure**, where a flawed ECDSA implementation reused a nonce, allowing the signing key to be recovered.

ECDSA nonce-generation problems have also affected cryptocurrency systems and wallets.

The broader lesson is:

> **A mathematically secure cryptographic algorithm can still fail catastrophically because of an implementation mistake.**

---

# Project Structure

```text
.
├── ecdsa_from_scratch.py
└── README.md
```

The Python file is intentionally kept as a single script so that the complete flow can be followed from:

```text
Curve parameters
      ↓
Point arithmetic
      ↓
Scalar multiplication
      ↓
Key generation
      ↓
Signing
      ↓
Verification
      ↓
Nonce-reuse attack
      ↓
Private-key recovery
```

---

# Important Security Notes

This project is **not production-ready cryptographic software**.

Several aspects are simplified for educational clarity.

### Do not use this implementation for:

* Cryptocurrency wallets
* Digital signatures
* Authentication
* TLS
* Secure messaging
* Key storage
* Production applications

For real applications, use a well-maintained and audited cryptographic implementation.

Examples include:

* Python `cryptography`
* Other established, audited cryptographic libraries

---

# What You Can Learn From This Project

By studying this implementation, you can connect several important concepts in applied cryptography:

### Mathematics

* Modular arithmetic
* Finite fields
* Modular inverses
* Elliptic curves
* Group operations
* Discrete logarithms

### Cryptography

* Public-key cryptography
* Digital signatures
* ECDSA
* Cryptographic nonces
* Hash functions
* Key generation
* Signature verification

### Security

* Cryptographic implementation failures
* Nonce-reuse attacks
* Private-key recovery
* Why randomness matters
* How mathematical weaknesses translate into practical attacks

---

# Possible Extensions

Some useful next steps for experimenting with the project:

* Implement deterministic ECDSA nonce generation using RFC 6979.
* Add public/private key serialization.
* Add compressed and uncompressed public-key formats.
* Implement SEC1 point encoding.
* Add DER signature encoding/decoding.
* Add unit tests for point arithmetic.
* Benchmark double-and-add scalar multiplication.
* Implement a small ECDSA signature scanner that detects repeated `r` values in a dataset.
* Compare the implementation against a vetted cryptographic library.
* Explore how biased or partially leaked nonces can also threaten private keys.
* Study lattice-based attacks against weak ECDSA nonce generation.

---

# Disclaimer

This repository is intended for **cryptography education, experimentation, and security research**.

The nonce-reuse demonstration intentionally recovers a private key generated by the program itself. It should only be used in controlled environments and with keys/data you are authorized to analyze.

**Never reuse ECDSA nonces in real systems.**
