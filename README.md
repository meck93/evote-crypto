# Crypto

Implementation of the elGamal cryposystem using finite field and elliptic curves.

## Finite Field ElGamal (`ff-elgamal`)

## Elliptic Curve ElGamal (`ec-elgamal`)

**Important**: `src/ec-elgamal` uses a curve that is not yet supported by the `elliptic` package. This curve is the curve25519 in Weierstrass form. We need to add curve25519 in Weierstrass form manually to the elliptic library since the required pull request has not been merged yet.

This is done via the script `copyCustomCurve.sh`. **You should not have to run this manually**.

`npm install` will automatically run `copyCustomCurve.sh` in it's `"postinstall"` task

## Publishing

### NPM & GitHub Packages

#### Authenticating to GitHub Packages

1. You need a personal access token to publish, install, and delete packages in GitHub Packages. The personal access token requires the following scopes: `read:packages, write:packages`.

2. You can authenticate to GitHub Packages with npm by either editing your per-user `~/.npmrc` file to include your personal access token or by logging in to npm on the command line using your username and personal access token.

   2.1. To authenticate with your personal access token include the following line in your `~/.npmrc` file:
   `//npm.pkg.github.com/:\_authToken=TOKEN`

   2.2. To authenticate by logging in to npm, use the npm login command:

   `npm login --registry=https://npm.pkg.github.com`

#### Publishing a package

By default, GitHub Packages publishes a package in the GitHub repository you specify in the name field of the `package.json` file. For example, you would publish this package named `@meck93/evote-crypto` to the meck93/evote-crypto GitHub repository.

1. Make sure the name in the `package.json` is the same as on Github `@OWNER/repo`
2. Add the following line to your `package.json`.

   2.1. HTTPS: `"repository": "git@github.com:meck93/evote-crypto.git"`

   2.2. SSH: `"repository": "https://github.com/meck93/evote-crypto.git"`

3. Publish the package: `npm publish`
