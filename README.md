# Crypto

Implementation of the elGamal cryposystem using finite field and elliptic curves.

## Finite Field ElGamal (`ff-elgamal`)

## Elliptic Curve ElGamal (`ec-elgamal`)

**Important**: `src/ec-elgamal` uses a curve that is not yet supported by the `elliptic` package. This curve is the curve25519 in Weierstrass form. We need to add curve25519 in Weierstrass form manually to the elliptic library since the required pull request has not been merged yet.

This is done via the script `copyCustomCurve.sh`. **You should not have to run this manually**.

`npm install` will automatically run `copyCustomCurve.sh` in it's `"postinstall"` task
