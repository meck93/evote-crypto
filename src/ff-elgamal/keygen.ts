import { FFelGamal } from '..'
import { KeyShareProof } from '../models'
import { getSecureRandomValue, newBN, BNpow, BNmul, BNdiv, BNadd } from './helper'

import BN = require('bn.js')

const web3 = require('web3')

export const generateSystemParameters = (p: number, q: number, g: number): FFelGamal.SystemParameters => {
  return { p: newBN(p), q: newBN(q), g: newBN(g) }
}

export const generateKeyShares = (params: FFelGamal.SystemParameters): FFelGamal.KeyShare => {
  const { p, q, g } = params

  // generate first key pair (sk, h)
  // pick two random values in Zq
  // compute private key share skr: sk*r mod q
  const sk: BN = getSecureRandomValue(q)
  const r: BN = getSecureRandomValue(q)
  const skr: BN = BNmul(sk, r, q)

  // compute public key share h_: g^skr mod p
  const h: BN = BNpow(g, skr, p)

  // generate a second key pair (a,b)
  // pick a random value from Zq and generate b: g^a mod p
  const a: BN = getSecureRandomValue(q)
  const b: BN = BNpow(g, a, p)

  return { h_: h, sk_: sk, r: r }
}

export const generateKeyGenerationProof = (params: FFelGamal.SystemParameters, share: FFelGamal.KeyShare, id: string): KeyShareProof => {
  const { p, q, g } = params
  const { h_, sk_, r } = share

  // generate a second key pair (a,b)
  // pick a random value from Zq and generate b: g^a mod p
  const a: BN = getSecureRandomValue(q)
  const b: BN = BNpow(g, a, p)

  // compute challenge hash(h_, a)
  const c: BN = generateChallenge(q, id, h_, b)

  // compute d = a + c*sk_*r
  const d: BN = BNadd(a, BNmul(c, BNmul(sk_, r, q), q), q)

  return { c: c, d: d }
}

export const verifyKeyGenerationProof = (params: FFelGamal.SystemParameters, proof: KeyShareProof, h_: BN, id: string): boolean => {
  const { p, q, g } = params
  const { c, d } = proof

  // recompute b = g^d/h_^c
  const b: BN = BNdiv(BNpow(g, d, p), BNpow(h_, c, p), p)

  // recompute the challenge c = hash(id, h_, b)
  const compC: BN = generateChallenge(q, id, h_, b)
  const check: boolean = c.eq(compC)

  console.log('b:\t', b.toString())
  console.log('compC:\t', compC.toString())

  return check
}

export const generateChallenge = (q: BN, uniqueID: string, h_: BN, b: BN): BN => {
  let c = web3.utils.soliditySha3(uniqueID, h_, b)
  c = web3.utils.toBN(c)
  c = c.mod(q)
  return c
}
