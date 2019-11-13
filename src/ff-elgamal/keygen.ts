import { FFelGamal } from '..'
import { getSecureRandomValue, newBN, BNpow, BNmul, BNdiv, BNadd } from './helper'
import { decodeMessage } from './encryption'
import { KeyShareProof, Cipher } from '../models'
import BN = require('bn.js')

const web3 = require('web3')

export const generateSystemParameters = (p: number, q: number, g: number): FFelGamal.SystemParameters => {
  return { p: newBN(p), q: newBN(q), g: newBN(g) }
}

export const generateKeyShares = (params: FFelGamal.SystemParameters): FFelGamal.KeyShare => {
  const { p, q, g } = params

  // generate first key pair (sk, h)
  // pick a random value in Zq
  const sk: BN = getSecureRandomValue(q)

  // compute public key share h_: g^sk mod p
  const h: BN = BNpow(g, sk, p)

  return { h_: h, sk_: sk }
}

export const generateKeyGenerationProof = (params: FFelGamal.SystemParameters, share: FFelGamal.KeyShare, id: string): KeyShareProof => {
  const { p, q, g } = params
  const { h_, sk_ } = share

  // generate a second key pair (a,b)
  // pick a random value from Zq and generate b: g^a mod p
  const a: BN = getSecureRandomValue(q)
  const b: BN = BNpow(g, a, p)

  // compute challenge hash(h_, b)
  const c: BN = generateChallenge(q, id, h_, b)

  // compute d = a + c*sk_
  const d: BN = BNadd(a, BNmul(c, sk_, q), q)

  return { c: c, d: d }
}

export const verifyKeyGenerationProof = (params: FFelGamal.SystemParameters, proof: KeyShareProof, h_: BN, id: string): boolean => {
  const { p, q, g } = params
  const { c, d } = proof

  // recompute b = g^d/h_^c
  const b: BN = BNdiv(BNpow(g, d, p), BNpow(h_, c, p), p)

  // recompute the challenge c = hash(id, h_, b)
  const c_: BN = generateChallenge(q, id, h_, b)
  const hashCheck: boolean = c.eq(c_)

  // verify that: g^d == b * h_^c
  const gPowd: BN = BNpow(g, d, p)
  const bhPowC: BN = BNmul(b, BNpow(h_, c, p), p)
  const dCheck: boolean = gPowd.eq(bhPowC)

  console.log("do the hashes match?\t", hashCheck)
  console.log('g^d == b * h_^c?\t', dCheck)
  console.log()

  return hashCheck && dCheck
}

export const combinePublicKeys = (params: FFelGamal.SystemParameters, publicKeyShares: BN[]): BN => {
  return publicKeyShares.reduce((product, share) => BNmul(product, share, params.p))
}

// NOTE: this should not be used as the distributed secret keys will become "useless"
// it is only used for testing purpose
export const combinePrivateKeys = (params: FFelGamal.SystemParameters, privateKeyShares: BN[]): BN => {
  return privateKeyShares.reduce((sum, share) => BNadd(sum, share, params.q))
}

export const decryptShare = (params: FFelGamal.SystemParameters, cipher: Cipher, secretKeyShare: BN): BN => {
  return BNpow(cipher.a, secretKeyShare, params.p)
}

export const combineDecryptedShares = (params: FFelGamal.SystemParameters, cipher: Cipher, decryptedShares: BN[]): BN => {
  const mh = BNdiv(cipher.b, decryptedShares.reduce((product, share) => BNmul(product, share, params.p)), params.p)

  // TODO: split PublicKey interface into system parameters (p,g,q) and the actual public key (h)
  // (h is not needed here)
  let m = decodeMessage(mh, { p: params.p, g: params.g, q: params.q, h: newBN(1) })

  return m
}

export const generateChallenge = (q: BN, uniqueID: string, h_: BN, b: BN): BN => {
  let c = web3.utils.soliditySha3(uniqueID, h_, b)
  c = web3.utils.toBN(c)
  c = c.mod(q)
  return c
}
