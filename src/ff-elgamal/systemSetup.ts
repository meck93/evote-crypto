/**
 * System Setup
 *
 * - generate system parameters p,q,g
 * - generate key pairs h,sk
 * - combine public/private key shares
 */

import BN = require('bn.js')
import { GlobalHelper } from '../index'
import { Helper, KeyPair, SystemParameters } from './index'

// generate system parameters p,q,g given p,g
export const generateSystemParameters = (p: number, g: number): SystemParameters => {
  return {
    p: GlobalHelper.newBN(p),
    q: GlobalHelper.newBN(Helper.getQofP(p)),
    g: GlobalHelper.newBN(g),
  }
}

// randomly generate a key pair h,sk given the system parameters p,q,g
export const generateKeyPair = (sp: SystemParameters): KeyPair => {
  const sk = GlobalHelper.getSecureRandomValue(sp.q) // pick a random value in Z_q
  const h = Helper.BNpow(sp.g, sk, sp.p) // compute public key h: g^sk mod p
  return { h, sk }
}

// generate system parameters p,q,g and a key pair h,sk given p,g
export const generateSystemParametersAndKeys = (
  p: number,
  g: number
): [SystemParameters, KeyPair] => {
  const sysParams = generateSystemParameters(p, g)
  const keyPair = generateKeyPair(sysParams)
  return [sysParams, keyPair]
}

// generate system parameters p,q,g and a key pair h,sk given p,g
// these parameters can be used for zero-knowledge proofs
export const generateSystemParametersAndKeysZKP = (
  p: number,
  g: number
): [SystemParameters, KeyPair] => {
  const sysParams = generateSystemParameters(p, g)
  const keyPair = generateKeyPair(sysParams)

  // verify that g^q mod p == 1 (this means: gcd(q,p) == 1)
  const test1 = Helper.BNpow(sysParams.g, sysParams.q, sysParams.p)
  if (!test1.eq(GlobalHelper.newBN(1))) {
    throw new Error(
      `g^q mod p != 1 (== ${test1.toNumber()}. for p: ${p}, q: ${sysParams.q.toNumber()} and g: ${g}`
    )
  }

  // verify that h^q mod p == 1 (this means: gcd(h,p) == 1)
  const test2 = Helper.BNpow(keyPair.h, sysParams.q, sysParams.p)
  if (!test2.eq(GlobalHelper.newBN(1))) {
    throw new Error(
      `h^q mod p != 1 (== ${test2.toNumber()}. for p: ${p}, q: ${sysParams.q.toNumber()} and g: ${g}`
    )
  }

  // verify that the public key h is not 1
  const test3 = keyPair.h.mod(sysParams.p)
  if (test3.eq(GlobalHelper.newBN(1))) {
    throw new Error(`h mod p == 1. for p: ${p}, q: ${sysParams.q.toNumber()} and g: ${g}`)
  }

  return [sysParams, keyPair]
}

// combines multiple public key shares to one public key
export const combinePublicKeys = (params: SystemParameters, publicKeyShares: BN[]): BN => {
  return publicKeyShares.reduce((product, share) => GlobalHelper.mulBN(product, share, params.p))
}

// combines multiple private key shares to one private key
// NOTE: this should not be used as the distributed secret keys will become "useless"
//       it is only used for testing purpose
export const combinePrivateKeys = (params: SystemParameters, privateKeyShares: BN[]): BN => {
  return privateKeyShares.reduce((sum, share) => GlobalHelper.addBN(sum, share, params.q))
}
