const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const crypto = require('crypto')
const BN = require('bn.js')

const UPPER_BOUND_RANDOM = ec.curve.n.sub(new BN(2, 10))
const printConsole = false
const RAND_SIZE_BYTES = 32

// fixed constants for values 1 -> generator and 0 -> generator^-1
const M_1 = ec.curve.g
const M_0 = ec.curve.g.neg()
printConsole && console.log('are the chosen on the curve?', ec.curve.validate(M_1) && ec.curve.validate(M_0))

function createZKP(message, pubK) {
  const alpha = getSecureRandom()
  const r1 = getSecureRandom()
  const d1 = getSecureRandom()
  const w = getSecureRandom()

  const [x, y] = encrypt(message, pubK, alpha)

  const xTd1 = x.mul(d1)
  const gTr1 = ec.curve.g.mul(r1)
  const a1 = gTr1.add(xTd1)
  printConsole && console.log('a1 is on curve?', ec.curve.validate(a1))

  const pubKTr1 = pubK.mul(r1)
  const yG = y.add(ec.curve.g)
  const yGTd1 = yG.mul(d1)
  const b1 = pubKTr1.add(yGTd1)
  printConsole && console.log('b1 is on the curve?', ec.curve.validate(b1))

  const a2 = ec.curve.g.mul(w)
  printConsole && console.log('a2 is on the curve?', ec.curve.validate(a2))

  const b2 = pubK.mul(w)
  printConsole && console.log('b2 is on the curve?', ec.curve.validate(b2))

  // TODO: change this ID with real ethereum address
  const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

  // TODO: fix the challenge generation such that the hash function output is always valid
  const challenge = generateChallenge(uniqueID, x, y, a1, a2, b1, b2)
  printConsole && console.log('c is greater than n', c.gt(ec.curve.n), 'c is greater than 1', c.gt(1))

  let d2 = challenge.sub(d1).mod(ec.curve.n)
  console.log('d2:', d2.isNeg(), 'c:', challenge.isNeg(), 'd1:', d1.isNeg())

  const intermediate = alpha.mul(d2).mod(ec.curve.n)
  const r2 = w.sub(intermediate)

  return [x, y, a1, a2, b1, b2, d1, d2, r1, r2, challenge]
}

function verifyZKP(proof, pubK) {
  const [x, y, a1, a2, b1, b2, d1, d2, r1, r2, c] = proof

  // validation of the hash - digest == hash(challenge)
  const d1d2 = d1.add(d2).mod(ec.curve.n)
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
  // console.log('a2', a2.getX().toString('hex'), a2.getY().toString('hex'))
  // console.log('a2', gTr2xTd2.getX().toString('hex'), gTr2xTd2.getY().toString('hex'))

  // validation of b2
  const pubKTr2 = pubK.mul(r2)
  const generator_inverted = ec.curve.g.neg()
  const yMinusG = y.add(generator_inverted)
  const yMinusGTd2 = yMinusG.mul(d2)
  const pubKTr2yMinusGTd2 = pubKTr2.add(yMinusGTd2)
  console.log('Is b2 the same?', pubKTr2yMinusGTd2.eq(b2))
}

function getSecureRandom() {
  let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
  let randomValue = new BN(randomBytes)

  // ensure that the random value is in range [1,n-2]
  while (!randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(1)) {
    randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
    randomValue = new BN(randomBytes, 'hex')
  }
  return randomValue
}

function convertECPointToString(point) {
  const pointAsJSON = point.toJSON()
  const Px = pointAsJSON[0].toString('hex')
  const Py = pointAsJSON[1].toString('hex')
  return Px + Py
}

function convertAllECPointsToString(points) {
  let asString = ''
  for (const point of points) {
    asString += convertECPointToString(point)
  }
  return asString
}

function generateChallenge(uniqueID, c1, c2, a1, a2, b1, b2) {
  const pointsAsString = convertAllECPointsToString([c1, c2, a1, a2, b1, b2])
  const input = uniqueID + pointsAsString

  const challenge = ec
    .hash()
    .update('test')
    .digest('hex')
  // return new BN(challenge, 'hex')
  return new BN(10, 'hex')
}

function encrypt(message, pubK, randomValue) {
  // compute c1: generator ec-multiply randomValue
  let c1 = ec.curve.g.mul(randomValue)
  printConsole && console.log('Is c1 on the curve?', ec.curve.validate(c1))

  // compute s: h^randomValue
  // whereby h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  const s = pubK.mul(randomValue)
  printConsole && console.log('Is point s on the curve?', ec.curve.validate(s))

  // compute c2: s ec-multiply message
  const c2 = s.add(message)
  printConsole && console.log('Is c2 on curve?', ec.curve.validate(c2))

  return [c1, c2]
}

function decrypt(cipherText, privK) {
  const c1 = cipherText[0]
  const c2 = cipherText[1]

  // compute s: c1^privateKey
  const s = c1.mul(privK)
  printConsole && console.log('is s on the curve?', ec.curve.validate(s))

  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = s.neg()
  printConsole && console.log('is s^-1 on the curve?', ec.curve.validate(s_inverse))

  // compute m: c2 ec-add s^-1
  const m = c2.add(s_inverse)
  printConsole && console.log('is m on curve?', ec.curve.validate(m))

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

for (let i = 0; i < 10; i++) {
  demo()
  console.log()
}
