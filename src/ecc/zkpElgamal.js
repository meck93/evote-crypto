const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const crypto = require('crypto')
const BN = require('bn.js')

const UPPER_BOUND_RANDOM = ec.curve.p.sub(new BN(2, 10))
const RAND_SIZE_BYTES = 33

// fix constants for values 1 -> generator and 0 -> generator^-1
const M_1 = ec.curve.g
const M_0 = ec.curve.g.neg()
console.log(
  'are the chosen on the curve?',
  ec.curve.validate(M_1) && ec.curve.validate(M_0)
)

function getSecureRandom() {
  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes)

  // ensure that the random value is in range [1,p-1]
  while (!randomValue.lte(UPPER_BOUND_RANDOM)) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes)
  }
  return randomValue
}

function createZKP(message, pubK) {
  const alpha = getSecureRandom()
  const r1 = getSecureRandom()
  const d1 = getSecureRandom()
  const w = getSecureRandom()

  const [x, y] = encrypt(message, pubK, alpha)

  const xTd1 = x.mul(d1)
  const gTr1 = ec.curve.g.mul(r1)
  const a1 = gTr1.add(xTd1)
  console.log('a1 is on curve?', ec.curve.validate(a1))

  const pubKTr1 = pubK.mul(r1)
  const yG = y.add(ec.curve.g)
  const yGTd1 = yG.mul(d1)
  const b1 = pubKTr1.add(yGTd1)
  console.log('b1 is on the curve?', ec.curve.validate(b1))

  const a2 = ec.curve.g.mul(w)
  console.log('a2 is on the curve?', ec.curve.validate(a2))

  const b2 = pubK.mul(w)
  console.log('b2 is on the curve?', ec.curve.validate(b2))

  const c = hash()

  // TODO: Think about how the negative number problem here can be fixed
  let d2 = c.sub(d1)
  d2 = d2.isNeg() ? d2.neg().mod(ec.curve.p) : d2.mod(ec.curve.p)
  console.log(d2)

  const intermediate = alpha.mul(d2).mod(ec.curve.p)
  let r2 = w.sub(intermediate)
  r2 = r2.isNeg() ? r2.neg().mod(ec.curve.p) : r2.mod(ec.curve.p)
  console.log(r2)

  return [x, y, a1, a2, b1, b2, d1, d2, r1, r2, c]
}

function verifyZKP(proof, pubK) {
  const [x, y, a1, a2, b1, b2, d1, d2, r1, r2, c] = proof

  // validation of the hash - digest == hash(challenge)
  const d1d2 = d1.add(d2).mod(ec.curve.p)
  console.log('Is the hash the same?', d1d2.eq(c))

  // validation of a1
  const gTr1 = ec.curve.g.mul(r1)
  const xTd1 = x.mul(d1)
  const gTr1xTd1 = gTr1.add(xTd1)
  console.log('Is a1 the same?', gTr1xTd1.eq(a1))

  // validation of b1
  const pubKTr1 = pubK.mul(r1)
  const yG = y.add(ec.curve.g)
  const yGTd1 = yG.mul(d1)
  const pubKTr1yGTd1 = pubKTr1.add(yGTd1)
  console.log('Is b1 the same?', pubKTr1yGTd1.eq(b1))

  // validation of a2
  const gTr2 = ec.curve.g.mul(r2)
  const xTd2 = x.mul(d2)
  const gTr2xTd2 = gTr2.add(xTd2)
  console.log('Is a2 the same?', gTr2xTd2.eq(a2))

  // validation of b2
  const pubKTr2 = pubK.mul(r2)
  const generator_inverted = ec.curve.g.neg()
  const yMinusG = y.add(generator_inverted)
  const yMinusGTd2 = yMinusG.mul(d2)
  const pubKTr2yMinusGTd2 = pubKTr2.add(yMinusGTd2)
  console.log('Is b2 the same?', pubKTr2yMinusGTd2.eq(b2))
}

function hash(uniqueID, c1, c2, a1, a2, b1, b2) {
  return new BN(50, 10)
}

function encrypt(message, pubK, randomValue) {
  // compute c1: generator ecc-multiply randomValue
  let c1 = ec.curve.g.mul(randomValue)
  console.log('Is c1 on the curve?', ec.curve.validate(c1))

  // compute s: h^randomValue
  // whereby h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  const s = pubK.mul(randomValue)
  console.log('Is point s on the curve?', ec.curve.validate(s))

  // compute c2: s ecc-multiply message
  const c2 = s.add(message)
  console.log('is c2 on curve?', ec.curve.validate(c2))

  return [c1, c2]
}

function decrypt(cipherText, privK) {
  const c1 = cipherText[0]
  const c2 = cipherText[1]

  // compute s: c1^privateKey
  const s = c1.mul(privK)
  console.log('is s on the curve?', ec.curve.validate(s))

  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = s.neg()
  console.log('is s^-1 on the curve?', ec.curve.validate(s_inverse))

  // compute m: c2 ecc-add s^-1
  const m = c2.add(s_inverse)
  console.log('is m on curve?', ec.curve.validate(m))

  return m
}

function demo() {
  const keyPair = ec.genKeyPair()
  const privateKey = keyPair.getPrivate()
  const publicKey = keyPair.getPublic()

  // const cipherText = encrypt(M_1, publicKey)
  // const plainText = decrypt(cipherText, privateKey)

  // console.log('are the messages the same?', plainText.eq(M_1))
  // console.log('plaintext is:', plainText.getX())

  const proof = createZKP(M_1, publicKey)
  const result = verifyZKP(proof, publicKey)
}

demo()
