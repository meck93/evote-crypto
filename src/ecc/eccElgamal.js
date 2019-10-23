const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const crypto = require('crypto')
const BN = require('bn.js')

const UPPER_BOUND_RANDOM = ec.curve.p.sub(new BN(2, 10))
const RAND_SIZE_BYTES = 33

const shouldLog = false

function getRandomValue() {
  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes)

  // ensure that the random value is in range [1,p-1]
  while (!randomValue.lte(UPPER_BOUND_RANDOM)) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes)
  }
  return randomValue
}

function encrypt(message, pubK) {
  const randBN = getRandomValue()

  // compute c1: generator ecc-multiply randomValue
  let c1 = ec.g.mul(randBN)
  shouldLog && console.log('Is c1 on the curve?', ec.curve.validate(c1))

  // compute s: h^randomValue
  // whereby h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  const s = pubK.mul(randBN)
  shouldLog && console.log('Is point s on the curve?', ec.curve.validate(s))

  // compute c2: s*message
  const c2 = s.add(message)
  shouldLog && console.log('is c2 on curve?', ec.curve.validate(c2))

  return [c1, c2]
}

function decrypt(cipherText, privK) {
  const c1 = cipherText[0]
  const c2 = cipherText[1]

  // compute s: c1^privateKey
  const s = c1.mul(privK)
  shouldLog && console.log('is s on the curve?', ec.curve.validate(s))

  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = s.neg()
  shouldLog && console.log('is s^-1 on the curve?', ec.curve.validate(s_inverse))

  // compute m: c2 ecc-add s^-1
  const m = c2.add(s_inverse)
  shouldLog && console.log('is m on curve?', ec.curve.validate(m))

  return m
}

function homomorphicAdd(cipher0, cipher1) {
  // adds two cipher texts together
  const c1 = cipher0[0].add(cipher1[0])
  const c2 = cipher0[1].add(cipher1[1])
  return [c1, c2]
}

module.exports = {
  homomorphicAdd,
  encrypt,
  decrypt,
  getRandomValue,
}
