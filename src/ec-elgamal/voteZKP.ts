const EC = require('elliptic').ec
const secp256k1 = new EC('secp256k1')
import { ECelGamal } from '../index'
import { ValidVoteProof } from '../models'
import { ECParams, ECCipher } from './models'
import BN = require('bn.js')
import { curve, ec } from 'elliptic'

const printConsole = false

const BNadd = (a: BN, b: BN, params: ECParams) => a.add(b).mod(params.n)
const BNsub = (a: BN, b: BN, params: ECParams) => a.sub(b).mod(params.n)
const BNmul = (a: BN, b: BN, params: ECParams) => a.mul(b).mod(params.n)

const ECpow = (a: curve.base.BasePoint, b: BN): curve.base.BasePoint => a.mul(b)
const ECmul = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b)
const ECdiv = (a: curve.base.BasePoint, b: curve.base.BasePoint): curve.base.BasePoint => a.add(b.neg())

// Generates a proof for an encrypted yes vote.
export function generateYesProof(encryptedVote: ECCipher, params: ECParams, id: string): ValidVoteProof {
  const { a, b, r } = encryptedVote
  const { h, g, n } = params

  if (r === undefined || r === null) {
    throw new Error('value r is undefined')
  }

  // generate fake values for m=0 part
  const c0: BN = ECelGamal.Helper.getSecureRandomValue()
  const f0: BN = ECelGamal.Helper.getSecureRandomValue()

  // compute fake a0. g^f0/a^c0
  const a0 = ECdiv(ECpow(g, f0), ECpow(a, c0))

  // compute fake b0. h^f0/b^c0
  const b0 = ECdiv(ECpow(h, f0), ECpow(b, c0))

  // generate proof for m=1 part
  const x: BN = ECelGamal.Helper.getSecureRandomValue()

  const a1 = ECpow(g, x)
  const b1 = ECpow(h, x)

  // generate the challenge
  const c = generateChallenge(n, id, a, b, a0, b0, a1, b1)
  const c1 = BNadd(n, BNsub(c, c0, params), params)

  // compute f1 = x + c1 * r (NOTE: mod q!) => in the EC case this is (mod n) instead of (mod p)
  const c1r = BNmul(c1, r, params)
  const f1 = BNadd(x, c1r, params)

  printConsole && console.log('a0 is on the curve?\t', secp256k1.curve.validate(a0))
  printConsole && console.log('b0 is on the curve?\t', secp256k1.curve.validate(b0))
  printConsole && console.log('a1 is on the curve?\t', secp256k1.curve.validate(a1))
  printConsole && console.log('b1 is on the curve?\t', secp256k1.curve.validate(b1))

  printConsole && console.log('c0\t\t\t\t', c0.toString('hex'))
  printConsole && console.log('f0\t\t\t\t', f0.toString('hex'))
  printConsole && console.log('x\t\t\t\t', x.toString('hex'))
  printConsole && console.log('c\t\t\t\t', c.toString('hex'))
  printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toString('hex'))
  printConsole && console.log('f1 = x + c1*r\t\t\t', f1.toString('hex'))
  printConsole && console.log()

  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

// Generates a proof for an encrypted no vote.
export function generateNoProof(encryptedVote: ECCipher, params: ECParams, id: string): ValidVoteProof {
  const { a, b, r } = encryptedVote
  const { h, g, n } = params

  if (r === undefined || r === null) {
    throw new Error('value r is undefined')
  }

  // generate fake values for m=0 part
  const c1: BN = ECelGamal.Helper.getSecureRandomValue()
  const f1: BN = ECelGamal.Helper.getSecureRandomValue()

  // compute fake b: b/g
  const b_ = ECdiv(b, g)

  // compute fake a0. g^f1/a^c1
  const a1 = ECdiv(ECpow(g, f1), ECpow(a, c1))

  // compute fake b0. h^f1/b^(b/g)
  const b1 = ECdiv(ECpow(h, f1), ECpow(b_, c1))

  // generate proof for m=1 part
  const x: BN = ECelGamal.Helper.getSecureRandomValue()

  const a0 = ECpow(g, x)
  const b0 = ECpow(h, x)

  // generate the challenge
  const c = generateChallenge(n, id, a, b, a0, b0, a1, b1)
  const c0 = BNadd(n, BNsub(c, c1, params), params)

  // compute f0 = x + c0 * r (NOTE: mod q!) => in the EC case this is (mod n) instead of (mod p)
  const c0r = BNmul(c0, r, params)
  const f0 = BNadd(x, c0r, params)

  printConsole && console.log('a1 is on the curve?\t', secp256k1.curve.validate(a1))
  printConsole && console.log('b1 is on the curve?\t', secp256k1.curve.validate(b1))
  printConsole && console.log('a0 is on the curve?\t', secp256k1.curve.validate(a0))
  printConsole && console.log('b0 is on the curve?\t', secp256k1.curve.validate(b0))

  printConsole && console.log('c1\t\t\t\t', c1.toString('hex'))
  printConsole && console.log('f1\t\t\t\t', f1.toString('hex'))
  printConsole && console.log('x\t\t\t\t', x.toString('hex'))
  printConsole && console.log('c\t\t\t\t', c.toString('hex'))
  printConsole && console.log('c0 = (q + (c - c1) % q) % q\t', c0.toString('hex'))
  printConsole && console.log('f0 = x + c0*r\t\t\t', f0.toString('hex'))
  printConsole && console.log()

  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

export function verifyZKP(encryptedVote: ECCipher, proof: ValidVoteProof, params: ECParams, id: string): boolean {
  const { a0, a1, b0, b1, c0, c1, f0, f1 } = proof
  const { h, g, n } = params
  const { a, b } = encryptedVote

  // verification g^f0 == a0*a^c0
  const l1 = ECpow(g, f0)
  const r1 = ECmul(a0, ECpow(a, c0))
  const v1 = l1.eq(r1)

  // verification g^f1 == a1*a^c1
  const l2 = ECpow(g, f1)
  const r2 = ECmul(a1, ECpow(a, c1))
  const v2 = l2.eq(r2)

  // verification h^f0 == b0 * b^c0
  const l3 = ECpow(h, f0)
  const r3 = ECmul(b0, ECpow(b, c0))
  console.log('r3 == l3?\t\t', l3.eq(r3), '\n')
  const v3 = l3.eq(r3)

  // verification h^f1 == b1 * (b/g)^c1
  const l4 = ECpow(h, f1)
  const r4 = ECmul(b1, ECpow(ECdiv(b, g), c1))
  const v4 = l4.eq(r4)

  // recompute the hash and verify
  const lc = BNadd(c0, c1, params)
  const rc = generateChallenge(n, id, a, b, a0, b0, a1, b1)
  const v5 = lc.eq(rc)

  printConsole && console.log('g^f0 == a0*a^c0:\t', v1)
  printConsole && console.log('g^f1 == a1*a^c1\t\t', v2)
  printConsole && console.log('h^f0 == b0*b^c0\t\t', v3)
  printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4)
  printConsole && console.log('c == c1 + c0\t\t', v5)
  printConsole && console.log()

  return v1 && v2 && v3 && v4 && v5
}

export function generateChallenge(n: BN, id: any, c1: any, c2: any, a1: any, a2: any, b1: any, b2: any) {
  const pointsAsString = convertAllECPointsToString([c1, c2, a1, a2, b1, b2])
  const input = id + pointsAsString

  let c = secp256k1
    .hash()
    .update(input)
    .digest('hex')

  c = new BN(c, 'hex')
  c = c.mod(n)

  return c
}

export function convertECPointToString(point: any) {
  const pointAsJSON = point.toJSON()
  const Px = pointAsJSON[0].toString('hex')
  const Py = pointAsJSON[1].toString('hex')
  return Px + Py
}

export function convertAllECPointsToString(points: any[]) {
  let asString = ''
  for (const point of points) {
    asString += convertECPointToString(point)
  }
  return asString
}
