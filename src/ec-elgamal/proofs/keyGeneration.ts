import BN = require('bn.js')
import { ec as EC } from 'elliptic'
import { ECelGamal } from '../..'
import { ECpow, ECdiv, ECmul, BNmul, BNadd, curvePointsToString } from '../helper'

import { CurvePoint } from '../models'
import { KeyGenerationProof } from './models'
import { SystemSetup, KeyPair } from '..'

const web3 = require('web3')

export const generateChallenge = (n: BN, uniqueID: string, h_: CurvePoint, b: CurvePoint): BN => {
  const pointsAsString = curvePointsToString([h_, b])
  const hashString: string = web3.utils.soliditySha3(uniqueID, pointsAsString)
  let c: BN = web3.utils.toBN(hashString)
  c = c.mod(n)
  return c
}

// 1. generate a "second" key pair (a,b)
// 2. compute challenge
// 3. compute d = a + c*sk
export const generate = (
  params: ECelGamal.SystemParameters,
  share: ECelGamal.KeyPair,
  id: string
): KeyGenerationProof => {
  const { n } = params
  const { h, sk } = share

  const keyPair: KeyPair = SystemSetup.generateKeyPair()
  const a: BN = keyPair.sk
  const b: CurvePoint = keyPair.h

  const c: BN = generateChallenge(n, id, h, b)
  const d: BN = BNadd(a, BNmul(c, sk, n), n)

  return { c: c, d: d }
}

// 1. recompute b = g^d / h^c
// 2. recompute the challenge c
// 3. verify that the challenge is correct
// 4. verify that: g^d == b * h^c
export const verify = (
  params: ECelGamal.SystemParameters,
  proof: KeyGenerationProof,
  h_: CurvePoint,
  id: string
): boolean => {
  const log = false
  const { n, g } = params
  const { c, d } = proof

  const b: CurvePoint = ECdiv(ECpow(g, d), ECpow(h_, c))

  const c_: BN = generateChallenge(n, id, h_, b)
  const hashCheck: boolean = c.eq(c_)

  const gPowd: CurvePoint = ECpow(g, d)
  const bhPowC: CurvePoint = ECmul(b, ECpow(h_, c))
  const dCheck: boolean = gPowd.eq(bhPowC)

  log && console.log('do the hashes match?\t', hashCheck)
  log && console.log('g^d == b * h_^c?\t', dCheck)
  log && console.log()

  return hashCheck && dCheck
}
