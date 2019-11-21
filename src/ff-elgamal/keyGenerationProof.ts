import { Helper, KeyShareProof, SystemParameters, KeyPair } from './index'
import BN = require('bn.js')

const web3 = require('web3')
const log = false

export const generateChallenge = (q: BN, uniqueID: string, h_: BN, b: BN): BN => {
  let c = web3.utils.soliditySha3(uniqueID, h_, b)
  c = web3.utils.toBN(c)
  c = c.mod(q)
  return c
}

export const generate = (
  params: SystemParameters,
  keyPair: KeyPair, // share
  id: string
): KeyShareProof => {
  const { p, q, g } = params
  const { h, sk } = keyPair

  // generate a second key pair (a,b)
  // pick a random value from Zq and generate b: g^a mod p
  const a: BN = Helper.getSecureRandomValue(q)
  const b: BN = Helper.BNpow(g, a, p)

  // compute challenge hash(h_, b)
  const c: BN = generateChallenge(q, id, h, b)

  // compute d = a + c*sk_
  const d: BN = Helper.BNadd(a, Helper.BNmul(c, sk, q), q)

  return { c: c, d: d }
}

export const verify = (
  params: SystemParameters,
  proof: KeyShareProof,
  h_: BN,
  id: string
): boolean => {
  const { p, q, g } = params
  const { c, d } = proof

  // recompute b = g^d/h_^c
  const b: BN = Helper.BNdiv(Helper.BNpow(g, d, p), Helper.BNpow(h_, c, p), p)

  // recompute the challenge c = hash(id, h_, b)
  const c_: BN = generateChallenge(q, id, h_, b)
  const hashCheck: boolean = c.eq(c_)

  // verify that: g^d == b * h_^c
  const gPowd: BN = Helper.BNpow(g, d, p)
  const bhPowC: BN = Helper.BNmul(b, Helper.BNpow(h_, c, p), p)
  const dCheck: boolean = gPowd.eq(bhPowC)

  log && console.log('do the hashes match?\t', hashCheck)
  log && console.log('g^d == b * h_^c?\t', dCheck)
  log && console.log()

  return hashCheck && dCheck
}
