# curve25519 (in Weierstrass form)

For more details about this curve, please see the `README` in the root folder.

In any case, this curve can be used like any other curve in the elliptic package. See the examples below.

```javascript
const curve = new EC('curve25519-weier')
```

We define the `curve` inside `src/ec-elgamal/curve.ts`.

```javascript
// activeCurve.ts
const EC = require('elliptic').ec
const curve25519 = new EC('curve25519-weier')
export const curveDefinition = curve25519
export const curve = curveDefinition.curve
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
    '20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9',
  ],
})
```
