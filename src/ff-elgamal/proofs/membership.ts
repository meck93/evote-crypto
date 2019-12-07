/**
 * Membership Proof
 *
 * ElGamal Finite Field Non-Interactive Zero-Knowledge Proof for Plaintext Membership
 * Using the Disjunctive Chaum-Pedersen Proof
 *
 * Proof that one of two statements is true without revealing which one.
 *
 * - generate and verify proofs
 */

import BN = require('bn.js')
import { Cipher, Helper, SystemParameters } from '../index'
import { MembershipProof } from './models'

const web3 = require('web3')
const printConsole = false

// modulo operations
const add = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNadd(a, b, sp.q)
const sub = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNsub(a, b, sp.q)
const mul = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNmul(a, b, sp.p)
const div = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNdiv(a, b, sp.p)
const pow = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNpow(a, b, sp.p)

// TODO: check paper https://eprint.iacr.org/2016/771.pdf why we should not hash a and b
const generateChallenge = (
  q: BN,
  uniqueID: string,
  a: BN,
  b: BN,
  a0: BN,
  b0: BN,
  a1: BN,
  b1: BN
): BN => {
  let c = web3.utils.soliditySha3(uniqueID, a, b, a0, b0, a1, b1)
  c = web3.utils.toBN(c)
  c = c.mod(q)

  return c
}

// generate a proof for an encrypted yes vote
// given:
// - cipher (a,b) = (g^r, h^r*g^m)
// - random value r used to encrypt the message
// steps:
// 1. generate fake values c0,f0 for m=0 (random values in Z_q)
// 2. compute fake (a0,b0) = (g^f0 / a^c0, h^f0 / b^c0)
// 3. generate proof for m=1
//    3.1 generate a random value x in Z_q
//    3.2 compute (a1,b1) =  (g^x, h^x)
// 4. generate the challenge c
// 5. compute c1 = c - c0
// 6. compute f1 = x + c1 * r (NOTE: mod q!)
export const generateYesProof = (
  cipher: Cipher,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): MembershipProof => {
  const { a, b, r } = cipher

  const c0 = Helper.getSecureRandomValue(sp.q)
  const f0 = Helper.getSecureRandomValue(sp.q)

  const a0 = div(pow(sp.g, f0, sp), pow(a, c0, sp), sp)
  const b0 = div(pow(pk, f0, sp), pow(b, c0, sp), sp)

  const x = Helper.getSecureRandomValue(sp.q)
  const a1 = pow(sp.g, x, sp)
  const b1 = pow(pk, x, sp)

  const c = generateChallenge(sp.q, uniqueID, a, b, a0, b0, a1, b1)
  const c1 = add(sp.q, sub(c, c0, sp), sp)

  const f1 = add(x, c1.mul(r as BN).mod(sp.q), sp)

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

  // TODO: proof is only c0,c1 f0,f1 (recompute a0,a1 and b0,b1 during the verification)
  return { a0, a1, b0, b1, c0, c1, f0, f1 }
}

// generate a proof for an encrypted no vote
// given:
// - cipher (a,b) = (g^r, h^r*g^m)
// - random value r used to encrypt the message
// steps:
// 1. generate fake values c1,f1 for m=1 (random values in Z_q)
// 2. compute fake b_ = b/g
// 3. compute fake (a1,b1) = (g^f1 / a^c1, h^f1 / (b/g)^c1)
// 4. generate proof for m=0
//    4.1 generate a random value x in Z_q
//    4.2 compute (a0,b0) =  (g^x, h^x)
// 5. generate the challenge c
// 6. compute c0 = c - c1
// 7. compute f0 = x + c0 * r (NOTE: mod q! = mod n!)
export const generateNoProof = (
  cipher: Cipher,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): MembershipProof => {
  const { a, b, r } = cipher

  const c1 = Helper.getSecureRandomValue(sp.q)
  const f1 = Helper.getSecureRandomValue(sp.q)

  const b_ = div(b, sp.g, sp)

  const a1 = div(pow(sp.g, f1, sp), pow(a, c1, sp), sp)
  const b1 = div(pow(pk, f1, sp), pow(b_, c1, sp), sp)

  const x = Helper.getSecureRandomValue(sp.q)
  const a0 = pow(sp.g, x, sp)
  const b0 = pow(pk, x, sp)

  const c = generateChallenge(sp.q, uniqueID, a, b, a0, b0, a1, b1)
  const c0 = add(sp.q, sub(c, c1, sp), sp)

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

// verification g^f0 == a0*a^c0
// verification g^f1 == a1*a^c1
// verification h^f0 == b0 * b^c0
// verification h^f1 == b1 * (b/g)^c1
// recompute the hash and verify
export const verify = (
  cipher: Cipher,
  proof: MembershipProof,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): boolean => {
  const { a, b } = cipher
  const { a0, a1, b0, b1, c0, c1, f0, f1 } = proof

  const v1 = pow(sp.g, f0, sp).eq(mul(a0, pow(a, c0, sp), sp))
  const v2 = pow(sp.g, f1, sp).eq(mul(a1, pow(a, c1, sp), sp))
  const v3 = pow(pk, f0, sp).eq(mul(b0, pow(b, c0, sp), sp))
  const v4 = pow(pk, f1, sp).eq(mul(b1, pow(div(b, sp.g, sp), c1, sp), sp))
  const v5 = c1
    .add(c0)
    .mod(sp.q)
    .eq(generateChallenge(sp.q, uniqueID, a, b, a0, b0, a1, b1))

  printConsole && console.log('g^f0 == a0*a^c0:\t', v1)
  printConsole && console.log('g^f1 == a1*a^c1\t', v2)
  printConsole && console.log('h^f0 == b0*b^c0\t\t', v3)
  printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4)
  printConsole && console.log('c == c1 + c0\t\t', v5)
  printConsole && console.log()

  return v1 && v2 && v3 && v4 && v5
}
