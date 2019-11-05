const BN = require('bn.js')
const hash = require('hash.js')
const random = require('random')

import { SumProof, Cipher } from '../models'
import { PublicKey } from './models'

const printConsole = true

export const newBN = (n: number) => new BN(n, 10)

// modulo operations
const add = (a: any, b: any, pk: PublicKey) => a.add(b).mod(pk.q)
const sub = (a: any, b: any, pk: PublicKey) => a.sub(b).mod(pk.q)
const mul = (a: any, b: any, pk: PublicKey) => a.mul(b).mod(pk.p)
const div = (a: any, b: any, pk: PublicKey) => mul(a, invm(b, pk), pk).mod(pk.p)
const pow = (a: any, b: any, pk: PublicKey) => a.pow(b).mod(pk.p)
const invm = (a: any, pk: PublicKey) => a.invm(pk.p)

// Generates a proof for the valid sum.
export function generateSumProof(cipher: Cipher, pk: PublicKey, uniqueID: string): SumProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b, r } = cipher

  // generate random value
  const x = newBN(random.int(1, pk.q - 1))

  // (g^x, h^x)
  const a1 = pow(pk.g, x, pk)
  const b1 = pow(pk.h, x, pk)

  // generate the challenge
  const c = generateChallenge(pk.q, uniqueID, a, b, a1, b1)

  // compute f = x + c * r (NOTE: mod q!)
  const cr = c.mul(r).mod(pk.q)
  const f = add(x, cr, pk)

  printConsole && console.log('x\t\t\t', x.toNumber())
  printConsole && console.log('a1\t\t\t', a1.toNumber())
  printConsole && console.log('b1\t\t\t', b1.toNumber())
  printConsole && console.log('c\t\t\t', c.toNumber())
  printConsole && console.log('f = x + c*r\t\t', f.toNumber())
  printConsole && console.log()

  return { a1, b1, c, f }
}

export function verifySumProof(cipher: Cipher, proof: SumProof, pk: any, uniqueID: string): boolean {
  const { a, b } = cipher
  const { a1, b1, c, f } = proof

  // verification g^f == a1*a^c
  const l1 = pow(pk.g, f, pk)
  const r1 = mul(a1, pow(a, c, pk), pk)
  const v1 = l1.eq(r1)

  // verification h^f == b1 * b^c
  const l2 = pow(pk.h, f, pk)
  const r2 = mul(b1, pow(b, c, pk), pk)
  const v2 = l2.eq(r2)

  // recompute the challenge
  const rc = generateChallenge(pk.q, uniqueID, a, b, a1, b1)
  const v3 = c.eq(rc)

  printConsole && console.log('g^f == a1*a^c:\t\t', v1)
  printConsole && console.log('h^f == b1*b^c\t\t', v2, l2.toNumber(), r2.toNumber())
  printConsole && console.log('c == H(ID,a,b,a1,b1)\t', v3)
  printConsole && console.log()

  return v1 && v2 && v3
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
