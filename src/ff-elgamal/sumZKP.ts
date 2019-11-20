import { Cipher, Helper, SumProof, SystemParameters } from './index'
import BN = require('bn.js')

const web3 = require('web3')
const printConsole = false

// modulo operations
const add = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNadd(a, b, sp.q)
const mul = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNmul(a, b, sp.p)
const pow = (a: BN, b: BN, sp: SystemParameters): BN => Helper.BNpow(a, b, sp.p)

export function generateChallenge(q: BN, uniqueID: string, a: BN, b: BN, a1: BN, b1: BN): BN {
  let c = web3.utils.soliditySha3(uniqueID, a, b, a1, b1)
  c = web3.utils.toBN(c)
  c = c.mod(q)
  return c
}

// Generates a proof for the valid sum.
export function generateSumProof(
  cipher: Cipher,
  sp: SystemParameters,
  sk: BN,
  uniqueID: string
): SumProof {
  // a = g^r, b = public_key i.e. h^r*g^m
  const { a, b }: Cipher = cipher

  // generate random value
  const x: BN = Helper.getSecureRandomValue(sp.q)

  // (a1, b1) = (a^x, g^x)
  const a1: BN = pow(a, x, sp)
  const b1: BN = pow(sp.g, x, sp)

  // generate the challenge
  // TODO: check paper https://eprint.iacr.org/2016/771.pdf why we should not hash a and b
  const c: BN = generateChallenge(sp.q, uniqueID, a, b, a1, b1)

  // compute f = x + c * sk (NOTE: mod q!)
  const cr: BN = c.mul(sk).mod(sp.q)
  const f: BN = add(x, cr, sp)

  // compute the decryption factor
  const d: BN = pow(a, sk, sp)

  printConsole && console.log('x\t\t\t', x.toNumber())
  printConsole && console.log('a1\t\t\t', a1.toNumber())
  printConsole && console.log('b1\t\t\t', b1.toNumber())
  printConsole && console.log('c\t\t\t', c.toNumber())
  printConsole && console.log('f = x + c*r\t\t', f.toNumber())
  printConsole && console.log()

  return { a1, b1, f, d } as SumProof
}

export function verifySumProof(
  cipher: Cipher,
  proof: SumProof,
  sp: SystemParameters,
  pk: BN,
  uniqueID: string
): boolean {
  const { a, b }: Cipher = cipher
  const { a1, b1, f, d }: SumProof = proof

  // recompute the challenge
  const c: BN = generateChallenge(sp.q, uniqueID, a, b, a1, b1)

  // verification a^f == a1 * d^c
  const l1: BN = pow(a, f, sp)
  const r1: BN = mul(a1, pow(d, c, sp), sp)
  const v1: boolean = l1.eq(r1)

  // verification g^f == b1 * h^c
  const l2: BN = pow(sp.g, f, sp)
  const r2: BN = mul(b1, pow(pk, c, sp), sp)
  const v2: boolean = l2.eq(r2)

  printConsole && console.log('a^f == a1*d^c:\t\t', v1, l1.toNumber(), r1.toNumber())
  printConsole && console.log('g^f == b1*h^c\t\t', v2, l2.toNumber(), r2.toNumber())
  printConsole && console.log()

  return v1 && v2
}

export function numbersToString(numbers: Array<BN>): string {
  let result = ''
  for (let i = 0; i < numbers.length; i++) {
    result += numbers[i].toJSON()
  }
  return result
}
