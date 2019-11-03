const BN = require('bn.js')
const hash = require('hash.js')
const random = require('random')

import { Proof, Cipher } from '../models'
import { PublicKey } from '../elgamal/models'

const printConsole = false

export function createProofForEncryptedVote(encryptedMessage: Cipher, pk: PublicKey): Proof {
  // extract encrypted message parts
  // a = g^r, b = public_key i.e. h^r*g^m
  const a = encryptedMessage.a
  const b = encryptedMessage.b

  // Generate fake values for m=0
  const c0 = new BN(random.int(1, pk.q - 1), 10)
  printConsole && console.log('c0\t\t\t', c0.toNumber())
  const f0 = new BN(random.int(1, pk.q - 1), 10)
  printConsole && console.log('f0\t\t\t', f0.toNumber())

  // compute fake a0. (a,b) = (a,b)
  const gPowF0 = pk.g.pow(f0).mod(pk.p)
  const aPowc0 = a.pow(c0).mod(pk.p)
  const aPowc0_inverse = aPowc0.invm(pk.p)
  const a0 = gPowF0.mul(aPowc0_inverse).mod(pk.p)
  printConsole && console.log('a0\t\t\t', a0.toNumber())

  // compute fake b0. (a,b) = (a,b)
  const hPowf0 = pk.h.pow(f0).mod(pk.p)
  const sPowc0 = b.pow(c0).mod(pk.p)
  const sPowc0_inverse = sPowc0.invm(pk.p)
  const b0 = hPowf0.mul(sPowc0_inverse).mod(pk.p)
  printConsole && console.log('b0\t\t\t', b0.toNumber())

  // Generate proof for m=1
  const x = new BN(random.int(1, pk.q - 1), 10)
  printConsole && console.log('x\t\t\t', x.toNumber())

  const a1 = pk.g.pow(x).mod(pk.p)
  printConsole && console.log('a1\t\t\t', a1.toNumber())

  const b1 = pk.h.pow(x).mod(pk.p)
  printConsole && console.log('b1\t\t\t', b1.toNumber())

  // // TODO: change this ID with real ethereum address
  const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

  // TODO: fix the challenge generation such that the hash function output is always valid
  const challenge = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1)
  // const challenge = new BN(random.int(1, pk.q - 1), 10)
  printConsole && console.log('c\t\t', challenge.toNumber())

  let c1 = challenge.sub(c0).mod(pk.q)
  printConsole && console.log('(c - c0) % q\t\t', c1.toNumber())

  c1 = c1 = pk.q.add(c1).mod(pk.q)
  printConsole && console.log('(q + (c - c0) % q) % q\t', c1.toNumber())

  // compute f1 = x + c1 * r
  const c1r = c1.mul(encryptedMessage.r).mod(pk.q)
  const f1 = x.add(c1r).mod(pk.q)
  printConsole && console.log('f1 = x + c1*r\t\t', f1.toNumber())
  printConsole && console.log()

  return { a, b, a0, a1, b0, b1, c0, c1, f0, f1, challenge }
}

export function verifyZKP(proof: Proof, pk: any): boolean {
  const { a, b, a0, a1, b0, b1, c0, c1, f0, f1, challenge } = proof

  // verificationg g^f0 == a0*a^c0
  const gPowF0 = pk.g.pow(f0).mod(pk.p)
  const aPowc0 = a.pow(c0).mod(pk.p)
  const a0rpowc0 = a0.mul(aPowc0).mod(pk.p)
  const v1 = gPowF0.eq(a0rpowc0)
  printConsole && console.log('g^f0 == a0*a^c0:\t', v1)
  printConsole && console.log('g^f0\t\t\t', gPowF0.toNumber())
  printConsole && console.log('a0*a^c0\t\t\t', a0rpowc0.toNumber())
  printConsole && console.log()

  // verification g^f1 == a1*a^c1Test
  const gPowF1 = pk.g.pow(f1).mod(pk.p)
  const c1PowC1 = a.pow(c1).mod(pk.p)
  const a1c1PowC1 = a1.mul(c1PowC1).mod(pk.p)
  const v2 = gPowF1.eq(a1c1PowC1)
  printConsole && console.log('g^f1 == a1*a^c1Test\t', v2)
  printConsole && console.log('g^f1\t\t\t', gPowF1.toNumber())
  printConsole && console.log('a1*a^c1Test\t\t', a1c1PowC1.toNumber())
  printConsole && console.log()

  // verification h^f0 == b0 * b^c0
  const hPowf0 = pk.h.pow(f0).mod(pk.p)
  const bPowC0 = b.pow(c0).mod(pk.p)
  const b0bPowC0 = b0.mul(bPowC0).mod(pk.p)
  const v3 = hPowf0.eq(b0bPowC0)
  printConsole && console.log('h^f0 == b0*b^c0\t\t', v3)
  printConsole && console.log()

  // verification h^f1 == b1 * (b/g)^c1Test
  const hPowf1 = pk.h.pow(f1).mod(pk.p)
  const g_inverse = pk.g.invm(pk.p)
  const bdivg = b.mul(g_inverse).mod(pk.p)
  const bdivgPowC1 = bdivg.pow(c1).mod(pk.p)
  const b1bdivgPowC1 = b1.mul(bdivgPowC1).mod(pk.p)
  const v4 = hPowf1.eq(b1bdivgPowC1)
  printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4)
  printConsole && console.log()

  // recompute the hash and verify
  const c = c1.add(c0).mod(pk.q)

  // TODO: Recompute the hash here instead of using the passed hash
  const v5 = challenge.eq(c)
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
  const pointsAsString = numbersToString([a, b, a0, b0, a1, b1])
  const input = uniqueID + pointsAsString

  let c = hash
    .sha256()
    .update(input)
    .digest('hex')

  c = new BN(c, 'hex')
  c = c.mod(q)

  return c
}
