const EC = require('elliptic').ec
const curve25519 = new EC('curve25519-weier')
export const curveDefinition = curve25519 // only used internally
export const curve = curveDefinition.curve // exported from crypto package
