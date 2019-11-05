const BN = require('bn.js')
const hash = require('hash.js')
const random = require('random')

import { SumProof, Cipher } from '../models'
import { PublicKey } from './models'

const printConsole = false

export const newBN = (n: number) => new BN(n, 10)

// modulo operations
const add = (a: any, b: any, pk: PublicKey) => a.add(b).mod(pk.q)
const mul = (a: any, b: any, pk: PublicKey) => a.mul(b).mod(pk.p)
const pow = (a: any, b: any, pk: PublicKey) => a.pow(b).mod(pk.p)

// Generates a proof for the valid sum.
export function generateSumProof(cipher: Cipher, pk: PublicKey, sk: any, uniqueID: string): SumProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b } = cipher

  // generate random value
  const x = newBN(random.int(1, pk.q - 1))

  // (a1, b1) = (a^x, g^x)
  const a1 = pow(a, x, pk)
  const b1 = pow(pk.g, x, pk)

  // generate the challenge
  const c = generateChallenge(pk.q, uniqueID, a, b, a1, b1)

  // compute f = x + c * sk (NOTE: mod q!)
  const cr = c.mul(sk).mod(pk.q)
  const f = add(x, cr, pk)

  // comute the decryption factor
  const d = pow(a, sk, pk)

  printConsole && console.log('x\t\t\t', x.toNumber())
  printConsole && console.log('a1\t\t\t', a1.toNumber())
  printConsole && console.log('b1\t\t\t', b1.toNumber())
  printConsole && console.log('c\t\t\t', c.toNumber())
  printConsole && console.log('f = x + c*r\t\t', f.toNumber())
  printConsole && console.log()

  return { a1, b1, f, d }
}

export function verifySumProof(cipher: Cipher, proof: SumProof, pk: any, uniqueID: string): boolean {
  const { a, b } = cipher
  const { a1, b1, f, d } = proof

  // recompute the challenge
  const c = generateChallenge(pk.q, uniqueID, a, b, a1, b1)

  // verification a^f == a1 * d^c
  const l1 = pow(a, f, pk)
  const r1 = mul(a1, pow(d, c, pk), pk)
  const v1 = l1.eq(r1)

  // verification g^f == b1 * h^c
  const l2 = pow(pk.g, f, pk)
  const r2 = mul(b1, pow(pk.h, c, pk), pk)
  const v2 = l2.eq(r2)

  printConsole && console.log('a^f == a1*d^c:\t\t', v1)
  printConsole && console.log('g^f == b1*h^c\t\t', v2, l2.toNumber(), r2.toNumber())
  printConsole && console.log()

  return v1 && v2
}

export function numbersToString(numbers: Array<any>) {
  let result = ''
  for (let i = 0; i < numbers.length; i++) {
    result += numbers[i].toJSON()
  }
  return result
}

export function generateChallenge(q: any, uniqueID: any, a: any, b: any, a1: any, b1: any) {
  const pointsAsString = numbersToString([a, b, a1, b1])
  const input = uniqueID + pointsAsString

  let c = hash
    .sha256()
    .update(input)
    .digest('hex')

  c = new BN(c, 'hex')
  c = c.mod(q)

  return c
}
