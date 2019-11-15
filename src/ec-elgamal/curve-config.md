# Adding curve25519 (in Weierstrass form) to Elliptic Library
We need to add curve25519 in Weierstrass form manually to the elliptic library since the required pull request has not been merged yet.

To add the curve, do the following:
- copy the configuration code below in to the file: `/node_modules/elliptic/lib/elliptic/curves.js`
- now, `curve25519-weier` can be instantiated via:
```javascript
const curve = new EC('curve25519-weier)
```

## Curve Configuration

```javascript
defineCurve('curve25519-weier', {
  type: 'short',
  prime: 'p25519',
  p: '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed',
  a: '2aaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaa aaaaaa984914a144',
  b: '7b425ed097b425ed 097b425ed097b425 ed097b425ed097b4 260b5e9c7710c864',
  n: '1000000000000000 0000000000000000 14def9dea2f79cd6 5812631a5cf5d3ed',
  hash: hash.sha256,
  gRed: false,
  g: [
    '2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a',
    '20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9'
  ]
});
```