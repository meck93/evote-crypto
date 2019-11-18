const EC = require('elliptic').ec
const curve25519 = new EC('curve25519-weier')
export const activeCurve = curve25519
