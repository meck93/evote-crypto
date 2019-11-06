const BN = require('bn.js')
const hash = require('hash.js')
const random = require('random')
const web3 = require('web3')

import { ValidVoteProof, Cipher } from '../models'
import { PublicKey } from './models'

const printConsole = false

export const newBN = (n: number) => new BN(n, 10)

// modulo operations
const add = (a: any, b: any, pk: PublicKey) => a.add(b).mod(pk.q)
const sub = (a: any, b: any, pk: PublicKey) => a.sub(b).mod(pk.q)
const mul = (a: any, b: any, pk: PublicKey) => a.mul(b).mod(pk.p)
const div = (a: any, b: any, pk: PublicKey) => mul(a, invm(b, pk), pk).mod(pk.p)
const pow = (a: any, b: any, pk: PublicKey) => a.pow(b).mod(pk.p)
const invm = (a: any, pk: PublicKey) => a.invm(pk.p)

// Generates a proof for an encrypted yes vote.
export function generateYesProof(cipher: Cipher, pk: PublicKey, uniqueID: string): ValidVoteProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b, r } = cipher

  // generate fake values for m=0
  const c0 = newBN(random.int(1, pk.q - 1))
  const f0 = newBN(random.int(1, pk.q - 1))

  // compute fake a0. (a,b) = (a,b)
  const a0 = div(pow(pk.g, f0, pk), pow(a, c0, pk), pk)

  // compute fake b0. (a,b) = (a,b)
  const b0 = div(pow(pk.h, f0, pk), pow(b, c0, pk), pk)

  // generate proof for m=1
  const x = newBN(random.int(1, pk.q - 1))

  const a1 = pow(pk.g, x, pk)
  const b1 = pow(pk.h, x, pk)

  // generate the challenge
  const c = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1)
  const c1 = add(pk.q, sub(c, c0, pk), pk)

  // compute f1 = x + c1 * r (NOTE: mod q!)
  const c1r = c1.mul(r).mod(pk.q)
  const f1 = add(x, c1r, pk)

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
export function generateNoProof(cipher: Cipher, pk: PublicKey, uniqueID: string): ValidVoteProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b, r } = cipher

  // generate fake values for m=1
  const c1 = newBN(random.int(1, pk.q - 1))
  const f1 = newBN(random.int(1, pk.q - 1))

  // compute fake b
  const b_ = div(b, pk.g, pk)

  // compute fake a1
  const a1 = div(pow(pk.g, f1, pk), pow(a, c1, pk), pk)

  // compute fake b1
  const b1 = div(pow(pk.h, f1, pk), pow(b_, c1, pk), pk)

  // generate proof for m=0
  const x = newBN(random.int(1, pk.q - 1))
  const a0 = pow(pk.g, x, pk)
  const b0 = pow(pk.h, x, pk)

  // generate the challenge
  const c = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1)
  const c0 = add(pk.q, sub(c, c1, pk), pk)

  // compute f0 = x + c0 * r (NOTE: mod q!)
  const f0 = add(x, c0.mul(r).mod(pk.q), pk)

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

export function verifyVoteProof(cipher: Cipher, proof: ValidVoteProof, pk: any, uniqueID: string): boolean {
  const { a, b } = cipher
  const { a0, a1, b0, b1, c0, c1, f0, f1 } = proof

  // verification g^f0 == a0*a^c0
  const l1 = pow(pk.g, f0, pk)
  const r1 = mul(a0, pow(a, c0, pk), pk)
  const v1 = l1.eq(r1)

  // verification g^f1 == a1*a^c1
  const l2 = pow(pk.g, f1, pk)
  const r2 = mul(a1, pow(a, c1, pk), pk)
  const v2 = l2.eq(r2)

  // verification h^f0 == b0 * b^c0
  const l3 = pow(pk.h, f0, pk)
  const r3 = mul(b0, pow(b, c0, pk), pk)
  const v3 = l3.eq(r3)

  // verification h^f1 == b1 * (b/g)^c1
  const l4 = pow(pk.h, f1, pk)
  const r4 = mul(b1, pow(div(b, pk.g, pk), c1, pk), pk)
  const v4 = l4.eq(r4)

  // recompute the hash and verify
  const lc = c1.add(c0).mod(pk.q)

  const rc = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1)
  const v5 = lc.eq(rc)

  printConsole && console.log('g^f0 == a0*a^c0:\t', v1)
  printConsole && console.log('g^f1 == a1*a^c1\t', v2)
  printConsole && console.log('h^f0 == b0*b^c0\t\t', v3)
  printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4)
  printConsole && console.log('c == c1 + c0\t\t', v5)
  printConsole && console.log()

  return v1 && v2 && v3 && v4 && v5
}

export function numbersToString(numbers: Array<any>) {
  let result = ''
  for (let i = 0; i < numbers.length; i++) {
    result += numbers[i].toJSON()
  }
  return result
}

export function generateChallenge(q: any, uniqueID: any, a: any, b: any, a0: any, b0: any, a1: any, b1: any) {
  let c = web3.utils.soliditySha3(uniqueID, a, b, a0, b0, a1, b1)
  c = web3.utils.toBN(c)
  c = c.mod(q)

  return c
}
