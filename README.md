# eVoting Cryptography

> _A cryptographic library developed for electronic voting using TypeScript. It includes an implementation of the ElGamal cryptosystem using finite fields and elliptic curves combined with non-interactive zero-knowledge proofs of knowledge and distributed key generation._
>
> _**This material is provided "as is", with absolutely no warranty expressed or implied. Any use is at your own risk.**_

## Overview

The library uses the following concepts to achieve the listed system properties:

- **ElGamal Cryptosystem**: Encryption and decryption of votes
- **Homomorphic Encryption**: Counting encrypted votes
- **Distributed Key Generation**: Multi-party asymmetric key generation
- **Non-Interactive Zero-Knowledge Proofs of Knowledge**: Proof of secret key knowledge and vote and decryption correctness

The library is divided into two parts: [Finite Fields](src/ff-elgamal) and [Elliptic Curves](src/ec-elgamal). Both parts mainly consist of the following modules:

- `SystemSetup`:
  - Key pair generation
  - Public key share combination
- `Encryption`:
  - Encryption/decryption of votes,
  - Homomorphic addition of encrypted votes
  - Vote sum decryption with private key shares
  - Combining decrypted vote sum shares
- `Voting`:
  - Generating yes and no votes
  - Tallying (= add and decrypt) votes
- `Proof`:
  - `KeyGeneration`: Proof of secret key knowledge
  - `Membership`: Proof of membership of a vote (0 or 1)
  - `Decryption`: Proof of correct decryption of the sum

TODO: link to final report for detailed introduction

## Cryptographic Building Blocks

### ElGamal

The ElGamal cryptosystem [1] is a public key cryptosystem defined over cyclic groups and is based on the difficulty of finding the discrete logarithm. This library uses cyclic groups and their modulo operations. To make the system safe, it uses a multiplicative prime-order group Z<sub>P</sub><sup>*</sup> where `p = 2*q + 1` and `q` are both prime numbers and `p` needs to be chosen very large.

The following values are used within the system:

- `SystemParameters`:
  - a prime number `p`
  - a prime number `q = (p - 1) / 2` (order of the group)
  - a group's generator `g`
- `KeyPair`:
  - a secret key `sk`: `0 < r < q`
  - a public key `h = g^sk mod p`
- `Cipher`: formed of `a` and `b`

#### Encryption

1. Pick a random value `r`: `0 < r < q`
2. Compute `a = g^r mod p`
3. Compute `s = h^r mod p`
4. Encode the message `m`: `mh = g^m mod p`
5. Compute `b = s*mh mod p`

=> Cipher (`a`, `b`)

#### Decryption

1. Compute `s = a^sk mod p`
2. Compute `s^(-1)` (multiplicative inverse of s)
3. Compute `mh = b * s^(-1)`
4. Decode `mh` using brute force

=> Plaintext `m`

### Homomorphic Encryption

Homomorphic encryption is used to perform computations on ciphertexts (here for addition) as if the computation was executed on plaintexts. This is the reason why `g^m` is used instead of just `m` during the encryption (encoding step).

The encrypted message is created as before (see 1). Due to 2, encrypted messages can be added as show in 3.

1. `E(m) = (a, b) = (g^r, h^r * g^m)`
2. `E(m1) * E(m2) = (g^(r1+r2), h^(r1+r2) * g^(m1+m2)) = E(m1 + m2)`
3. `E(m3) = E(m1 + m2) = (E(m1)_a * E(m2)_a, E(m1)_b * E(m2)_b)`

### Distributed Key Generation/Decryption

As shown above, the library can be used with a single key pair `(sk, h)`. To use the system with not only one but multiple parties (each party `i` having its own key pair `(sk_i, h_i)`), the key generation and decryption algorithms need to be adjusted. The encryption step however stays the same.

This library uses a setting where `n` out of `n` keys need to be present for decrypting a cipher [8]. To create a key pair, each party `1 <= i <= n` individually picks a secret key and generates the public key as shown before (see 1). All the public keys are then combined to one public key used for encryption (see 2). To decrypt a cipher, two steps are needed. First, each party uses its private key `sk_i` to create a decrypted share `d_i` (see 3). Then, these shares are combined to get the plaintext `m` (see 4).

1. `(sk_i, h_i = g^sk_i mod p)`
2. `h = h_1 * ... * h_i * ... * h_n mod p`
3. `d_i = a^sk_i mod p` with cipher `(a, b)`
4. `m = b / (d_1 * ... * d_i * ... * d_n) mod p` (where `x/y = x*y^-1` with `y^-1` being the multiplicative inverse of `y`)

### Non-Interactive Zero-Knowledge Proofs of Knowledge

To convince a verifier that a prover knows some secret without revealing the actual secret, a zero-knowledge proof of knowledge can be used. This requires to follow special sigma protocols which include some (three-move) interactions between the verifier and the prover where the prover makes a commitment and the verifier answers with some random challenge the prover needs to respond to.

Such interactive proof systems can be made non-interactive by applying the Fiat-Shamir heuristic [2] by using a cryptographic hash function as a random oracle for computing the challenge of the verifier. According to [3], the Fiat-Shamir transformation is "weak" (e.g., under certain circumstances, a proof might be verified correctly even the initial commitment was tapered with) when only the commitment is hashed (as described in [4]). However, it is considered "strong" [3], if the statement to be proved is also hashed (as suggested in [5, 6]). Thus, this library hashes both the statement to be proved and the commitment when generating the challenge.

The Fiat-Shamir transformation is applied to the Schnorr [5], Chaum Pedersen [6], and Disjuntive Chaum-Pedersen protocols as depicted in the following sections.

#### Key Generation: Schnorr Proof

After the (distributed) key generation as described above, the Schnorr Proof [7] is used to prove that a party knows the corresponding secret key `sk` to the published public key `h = g^sk`. It is a proof of knowledge of a discrete logarithm of `sk = log_g(g^sk)`.

#### Decryption: Chaum-Pedersen Proof

The Chaum-Pedersen Proof [6] is used for proving that the decryption (`m = (a^sk)^-1 * b` with cipher (`a`, `b`)) was done using the corresponding private key `sk` to the public key `h = g^sk` used for the encryption. It is a proof of discrete logarithm equality of `log_g(g^sk) = log_h(h^r)`.

#### Membership: Disjunctive Chaum-Pedersen Proof

The Disjunctive Chaum-Pedersen Proof is used for proving that one out of two statements is true without revealing which one is correct. Here, this proof is used to prove that an encrypted vote (0 or 1) is either 0 or 1 while not revealing the vote's actual value.

## Implementation

The respective implementations of the homomorphic ElGamal cryptosystem using distributed keys and non-interactive zero-knowledge proofs of knowledge can be found here: [Finite Fields](src/ff-elgamal) and [Elliptic Curves](src/ec-elgamal)

**Important for the Elliptic Curve Implementation**:

`src/ec-elgamal` uses the **curve25519** in Weierstrass form, which is not yet supported by the `elliptic` package used in this project to operate on elliptic curves. Since the required pull request has not been merged yet, this curve is manually added to the elliptic library.

This is done via the script `copyCustomCurve.sh`. **You should not have to run this manually**.

`npm install` will automatically run `copyCustomCurve.sh` in it's `"postinstall"` task.

## Publishing the Library

### NPM & GitHub Packages

#### Authenticating to GitHub Packages

1. You need a personal access token to publish, install, and delete packages in GitHub Packages. The personal access token requires the following scopes: `read:packages, write:packages`.

2. You can authenticate to GitHub Packages with npm by either editing your per-user `~/.npmrc` file to include your personal access token or by logging in to npm on the command line using your username and personal access token.

   2.1. To authenticate with your personal access token include the following line in your `~/.npmrc` file:
   `//npm.pkg.github.com/:\_authToken=TOKEN`

   2.2. To authenticate by logging in to npm, use the npm login command:

   `npm login --registry=https://npm.pkg.github.com`

#### Publishing a Package

By default, GitHub Packages publishes a package in the GitHub repository you specify in the name field of the `package.json` file. For example, you would publish this package named `@meck93/evote-crypto` to the meck93/evote-crypto GitHub repository.

1. Make sure the name in the `package.json` is the same as on Github `@OWNER/repo`
2. Add the following line to your `package.json`.

   2.1. HTTPS: `"repository": "git@github.com:meck93/evote-crypto.git"`

   2.2. SSH: `"repository": "https://github.com/meck93/evote-crypto.git"`

3. Create a new version using `npm version [<newversion> | major | minor | patch] -m "Upgarde to %s for...`

- The `%s` will be automatically replace with the new version.
- A git commit and tag for the new version will be created automatically.
- **Note.** The command will only work if the repository is clean. No uncommited changes.

4. Publish the package: `npm publish`

## References

[1] Taher El Gamal: **A public key cryptosystem and a signature scheme based on discrete logarithms.** IEEE Trans. Information Theory 31(4): 469-472 (1985) - [PDF](https://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf), [dblp](https://dblp.uni-trier.de/rec/html/journals/tit/Elgamal85)

[2] Amos Fiat, Adi Shamir: **How to Prove Yourself: Practical Solutions to Identification and Signature Problems.** CRYPTO 1986: 186-194 - [PDF](https://link.springer.com/content/pdf/10.1007%2F3-540-47721-7_12.pdf), [dblp](https://dblp.uni-trier.de/rec/html/conf/crypto/FiatS86)

[3] David Bernhard, Olivier Pereira, Bogdan Warinschi: **How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios.** IACR Cryptology ePrint Archive 2016: 771 (2016) - [PDF](https://eprint.iacr.org/2016/771.pdf), [dblp](https://dblp.org/rec/journals/iacr/BernhardPW16)

[4] Mihir Bellare, Phillip Rogaway: **Random Oracles are Practical: A Paradigm for Designing Efficient Protocols.** ACM Conference on Computer and Communications Security 1993: 62-73 - [PDF](https://cseweb.ucsd.edu/~mihir/papers/ro.pdf), [dblp](    https://dblp.org/rec/conf/ccs/BellareR93)

[5] Claus-Peter Schnorr: **Efficient Signature Generation by Smart Cards.** J. Cryptology 4(3): 161-174 (1991) - [PDF](https://www.researchgate.net/profile/Claus_Schnorr/publication/227088517_Efficient_signature_generation_by_smart_cards/links/0046353849579ce09c000000/Efficient-signature-generation-by-smart-cards.pdf), [dblp](ttps://dblp.org/rec/journals/joc/Schnorr91)

[6] David Chaum, Torben P. Pedersen: **Wallet Databases with Observers.** CRYPTO 1992: 89-105 - [PDF](https://www.chaum.com/publications/Wallet_Databases.pdf), [dblp](https://dblp.org/rec/conf/crypto/ChaumP92)

[7] Feng Hao: **Schnorr Non-interactive Zero-Knowledge Proof.** RFC 8235: 1-13 (2017) - [RFC](https://tools.ietf.org/html/rfc8235), [PDF](https://tools.ietf.org/pdf/rfc8235.pdf), [dblp](https://dblp.org/rec/journals/rfc/rfc8235)

[8] David Bernhard, Bogdan Warinschi: **Cryptographic Voting - A Gentle Introduction.** IACR Cryptology ePrint Archive 2016: 765 (2016) - [PDF](https://eprint.iacr.org/2016/765.pdf), [dblp](https://dblp.org/rec/journals/iacr/BernhardW16)

## Authors

- **Moritz Eck** - [meck93](https://github.com/meck93)
- **Alex Scheitlin** - [alexscheitlin](https://github.com/alexscheitlin)
- **Nik Zaugg** - [nikzaugg](https://github.com/nikzaugg)

## License

This project is licensed under the [MIT License](LICENSE).
