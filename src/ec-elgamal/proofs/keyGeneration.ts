import BN = require('bn.js')

import { CurvePoint, Helper, KeyPair, SystemSetup, SystemParameters } from '../index'
import { KeyGenerationProof } from './index'

const web3 = require('web3')

export const generateChallenge = (n: BN, uniqueID: string, h_: CurvePoint, b: CurvePoint): BN => {
  const pointsAsString = Helper.curvePointsToString([h_, b])
  const hashString: string = web3.utils.soliditySha3(uniqueID, pointsAsString)
  let c: BN = web3.utils.toBN(hashString)
  c = c.mod(n)
  return c
}

// 1. generate a "second" key pair (a,b)
// 2. compute challenge
// 3. compute d = a + c*sk
export const generate = (
  params: SystemParameters,
  share: KeyPair,
  id: string
): KeyGenerationProof => {
  const { n } = params
  const { h, sk } = share

  const keyPair: KeyPair = SystemSetup.generateKeyPair()
  const a: BN = keyPair.sk
  const b: CurvePoint = keyPair.h

  const c: BN = generateChallenge(n, id, h, b)
  const d: BN = Helper.BNadd(a, Helper.BNmul(c, sk, n), n)

  return { c: c, d: d }
}

// 1. recompute b = g^d / h^c
// 2. recompute the challenge c
// 3. verify that the challenge is correct
// 4. verify that: g^d == b * h^c
export const verify = (
  params: SystemParameters,
  proof: KeyGenerationProof,
  h_: CurvePoint,
  id: string
): boolean => {
  const log = false
  const { n, g } = params
  const { c, d } = proof

  const b: CurvePoint = Helper.ECdiv(Helper.ECpow(g, d), Helper.ECpow(h_, c))

  const c_: BN = generateChallenge(n, id, h_, b)
  const hashCheck: boolean = c.eq(c_)

  const gPowd: CurvePoint = Helper.ECpow(g, d)
  const bhPowC: CurvePoint = Helper.ECmul(b, Helper.ECpow(h_, c))
  const dCheck: boolean = gPowd.eq(bhPowC)

  log && console.log('do the hashes match?\t', hashCheck)
  log && console.log('g^d == b * h_^c?\t', dCheck)
  log && console.log()

  return hashCheck && dCheck
}
