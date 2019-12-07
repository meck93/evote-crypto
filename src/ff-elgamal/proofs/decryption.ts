/**
 * Decryption Proof
 *
 * ElGamal Finite Field Non-Interactive Zero-Knowledge Proof for Decryption
 * Using the Chaum-Pedersen Proof
 *
 * Proving that the decryption is done using the corresponding private key to the
 * public key used for the encryption.
 *
 * - generate and verify proofs
 */

import BN = require('bn.js')
import { GlobalHelper } from '../../index'
import { Cipher, SystemParameters } from '../index'
import { DecryptionProof } from './models'

const web3 = require('web3')
const printConsole = false

// modulo operations
const add = (a: BN, b: BN, sp: SystemParameters): BN => GlobalHelper.addBN(a, b, sp.q)
const mul = (a: BN, b: BN, sp: SystemParameters): BN => GlobalHelper.mulBN(a, b, sp.p)
const pow = (a: BN, b: BN, sp: SystemParameters): BN => GlobalHelper.powBN(a, b, sp.p)

// TODO: check paper https://eprint.iacr.org/2016/771.pdf why we should not hash a and b
const generateChallenge = (q: BN, uniqueID: string, a: BN, b: BN, a1: BN, b1: BN): BN => {
  let c = web3.utils.soliditySha3(uniqueID, a, b, a1, b1)
  c = web3.utils.toBN(c)
  c = c.mod(q)
  return c
}

// generate a proof for the decryption
// given:
// - a,b: cipher (a = g^r, b = h^r*g^m)
// steps:
// 1. generate random value x
// 2. compute (a1, b1) = (a^x, g^x)
// 3. generate the challenge
// 3. compute f = x + c * sk (NOTE: mod q!)
// 4. compute the decryption factor d = a^r
export const generate = (
  cipher: Cipher,
  sp: SystemParameters,
  sk: BN,
  uniqueID: string
): DecryptionProof => {
  const { a, b }: Cipher = cipher

  const x: BN = GlobalHelper.getSecureRandomValue(sp.q)

  const a1: BN = pow(a, x, sp)
  const b1: BN = pow(sp.g, x, sp)

  const c: BN = generateChallenge(sp.q, uniqueID, a, b, a1, b1)
  const f: BN = add(x, c.mul(sk).mod(sp.q), sp)
  const d: BN = pow(a, sk, sp)

  printConsole && console.log('x\t\t\t', x.toNumber())
  printConsole && console.log('a1\t\t\t', a1.toNumber())
  printConsole && console.log('b1\t\t\t', b1.toNumber())
  printConsole && console.log('c\t\t\t', c.toNumber())
  printConsole && console.log('f = x + c*r\t\t', f.toNumber())
  printConsole && console.log()

  return { a1, b1, f, d } as DecryptionProof
}

// verify a proof for the decryption
// 1. recompute the challenge
// 2. verification a^f == a1 * d^c
// 3. verification g^f == b1 * h^c
export const verify = (
  cipher: Cipher,
  proof: DecryptionProof,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): boolean => {
  const { a, b }: Cipher = cipher
  const { a1, b1, f, d }: DecryptionProof = proof

  const c: BN = generateChallenge(sp.q, uniqueID, a, b, a1, b1)

  const l1: BN = pow(a, f, sp)
  const r1: BN = mul(a1, pow(d, c, sp), sp)
  const v1: boolean = l1.eq(r1)

  const l2: BN = pow(sp.g, f, sp)
  const r2: BN = mul(b1, pow(pk, c, sp), sp)
  const v2: boolean = l2.eq(r2)

  printConsole && console.log('a^f == a1*d^c:\t\t', v1, l1.toNumber(), r1.toNumber())
  printConsole && console.log('g^f == b1*h^c\t\t', v2, l2.toNumber(), r2.toNumber())
  printConsole && console.log()

  return v1 && v2
}
