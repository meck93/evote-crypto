import { Cipher, Helper, ValidVoteProof, SystemParameters } from './index'
import BN = require('bn.js')

const web3 = require('web3')
const printConsole = false

// modulo operations
const add = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNadd(a, b, sp.q)
const sub = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNsub(a, b, sp.q)
const mul = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNmul(a, b, sp.p)
const div = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNdiv(a, b, sp.p)
const pow = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNpow(a, b, sp.p)

export function generateChallenge(
  q: BN,
  uniqueID: string,
  a: BN,
  b: BN,
  a0: BN,
  b0: BN,
  a1: BN,
  b1: BN
): BN {
  let c = web3.utils.soliditySha3(uniqueID, a, b, a0, b0, a1, b1)
  c = web3.utils.toBN(c)
  c = c.mod(q)

  return c
}

// Generates a proof for an encrypted yes vote.
export function generateYesProof(
  cipher: Cipher,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): ValidVoteProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b, r } = cipher

  // generate fake values for m=0
  const c0 = Helper.getSecureRandomValue(sp.q)
  const f0 = Helper.getSecureRandomValue(sp.q)

  // compute fake a0. (a,b) = (a,b)
  const a0 = div(pow(sp.g, f0, sp), pow(a, c0, sp), sp)

  // compute fake b0. (a,b) = (a,b)
  const b0 = div(pow(pk, f0, sp), pow(b, c0, sp), sp)

  // generate proof for m=1
  const x = Helper.getSecureRandomValue(sp.q)

  const a1 = pow(sp.g, x, sp)
  const b1 = pow(pk, x, sp)

  // generate the challenge
  // TODO: check paper https://eprint.iacr.org/2016/771.pdf why we should not hash a and b
  const c = generateChallenge(sp.q, uniqueID, a, b, a0, b0, a1, b1)
  const c1 = add(sp.q, sub(c, c0, sp), sp)

  // compute f1 = x + c1 * r (NOTE: mod q!)
  const c1r = c1.mul(r as BN).mod(sp.q)
  const f1 = add(x, c1r, sp)

  printConsole && console.log('c0\t\t\t', c0.toNumber())
  printConsole && console.log('f0\t\t\t', f0.toNumber())
  printConsole && console.log('a0\t\t\t', a0.toNumber())
  printConsole && console.log('b0\t\t\t', b0.toNumber())
  printConsole && console.log('x\t\t\t', x.toNumber())
  printConsole && console.log('a1\t\t\t', a1.toNumber())
  printConsole && console.log('b1\t\t\t', b1.toNumber())
  printConsole && console.log('c\t\t', c.toNumber())
  printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toNumber())
  printConsole && console.log('f1 = x + c1*r\t\t', f1.toNumber())
  printConsole && console.log()

  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

// Generates a proof for an encrypted no vote.
export function generateNoProof(
  cipher: Cipher,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): ValidVoteProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b, r } = cipher

  // generate fake values for m=1
  const c1 = Helper.getSecureRandomValue(sp.q)
  const f1 = Helper.getSecureRandomValue(sp.q)

  // compute fake b
  const b_ = div(b, sp.g, sp)

  // compute fake a1
  const a1 = div(pow(sp.g, f1, sp), pow(a, c1, sp), sp)

  // compute fake b1
  const b1 = div(pow(pk, f1, sp), pow(b_, c1, sp), sp)

  // generate proof for m=0
  const x = Helper.getSecureRandomValue(sp.q)
  const a0 = pow(sp.g, x, sp)
  const b0 = pow(pk, x, sp)

  // generate the challenge
  // TODO: check paper https://eprint.iacr.org/2016/771.pdf why we should not hash a and b
  const c = generateChallenge(sp.q, uniqueID, a, b, a0, b0, a1, b1)
  const c0 = add(sp.q, sub(c, c1, sp), sp)

  // compute f0 = x + c0 * r (NOTE: mod q!)
  const f0 = add(x, c0.mul(r as BN).mod(sp.q), sp)

  printConsole && console.log('c0\t\t\t', c0.toNumber())
  printConsole && console.log('f0\t\t\t', f0.toNumber())
  printConsole && console.log('a0\t\t\t', a0.toNumber())
  printConsole && console.log('b0\t\t\t', b0.toNumber())
  printConsole && console.log('x\t\t\t', x.toNumber())
  printConsole && console.log('a1\t\t\t', a1.toNumber())
  printConsole && console.log('b1\t\t\t', b1.toNumber())
  printConsole && console.log('c\t\t', c.toNumber())
  printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toNumber())
  printConsole && console.log('f1 = x + c1*r\t\t', f1.toNumber())
  printConsole && console.log()

  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

export function verifyVoteProof(
  cipher: Cipher,
  proof: ValidVoteProof,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): boolean {
  const { a, b } = cipher
  const { a0, a1, b0, b1, c0, c1, f0, f1 } = proof

  // verification g^f0 == a0*a^c0
  const l1 = pow(sp.g, f0, sp)
  const r1 = mul(a0, pow(a, c0, sp), sp)
  const v1 = l1.eq(r1)

  // verification g^f1 == a1*a^c1
  const l2 = pow(sp.g, f1, sp)
  const r2 = mul(a1, pow(a, c1, sp), sp)
  const v2 = l2.eq(r2)

  // verification h^f0 == b0 * b^c0
  const l3 = pow(pk, f0, sp)
  const r3 = mul(b0, pow(b, c0, sp), sp)
  const v3 = l3.eq(r3)

  // verification h^f1 == b1 * (b/g)^c1
  const l4 = pow(pk, f1, sp)
  const r4 = mul(b1, pow(div(b, sp.g, sp), c1, sp), sp)
  const v4 = l4.eq(r4)

  // recompute the hash and verify
  const lc = c1.add(c0).mod(sp.q)

  const rc = generateChallenge(sp.q, uniqueID, a, b, a0, b0, a1, b1)
  const v5 = lc.eq(rc)

  printConsole && console.log('g^f0 == a0*a^c0:\t', v1)
  printConsole && console.log('g^f1 == a1*a^c1\t', v2)
  printConsole && console.log('h^f0 == b0*b^c0\t\t', v3)
  printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4)
  printConsole && console.log('c == c1 + c0\t\t', v5)
  printConsole && console.log()

  return v1 && v2 && v3 && v4 && v5
}
