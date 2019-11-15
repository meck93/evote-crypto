import { encrypt, homomorphicAdd, decrypt } from './encryption'
import { VoteZKP } from './'
import { SumZKP } from './'
import { ECCipher, ECParams, ECParamsTransfer } from './models'
import { curve } from 'elliptic'

import BN = require('bn.js')
import { ValidVoteProof, SumProof } from '../models'

const EC = require('elliptic').ec
const curve25519 = new EC('curve25519-weier')

const startingPoint = curve25519.curve.g
const infinityPoint = startingPoint.add(startingPoint.neg())

export const generateYesVote = (pk: string | curve.base.BasePoint): ECCipher => {
  let publicKey

  if (typeof pk === 'string' || pk instanceof String) {
    publicKey = curve25519.keyFromPublic(pk, 'hex').pub
  } else {
    publicKey = pk
  }

  return encrypt(startingPoint, publicKey)
}

export const generateNoVote = (pk: string | curve.base.BasePoint): ECCipher => {
  let publicKey

  if (typeof pk === 'string' || pk instanceof String) {
    publicKey = curve25519.keyFromPublic(pk, 'hex').pub
  } else {
    publicKey = pk
  }

  return encrypt(startingPoint.neg(), publicKey)
}

export const addVotes = (votes: ECCipher[], pk: string | curve.base.BasePoint): ECCipher => {
  let publicKey

  if (typeof pk === 'string' || pk instanceof String) {
    publicKey = curve25519.keyFromPublic(pk, 'hex').pub
  } else {
    publicKey = pk
  }

  return votes.reduce((previous, current) => homomorphicAdd(previous, current), encrypt(infinityPoint, publicKey))
}

export const findPoint = (point: curve.base.BasePoint): number => {
  let pointPositive = startingPoint
  let pointNegative = startingPoint.neg()
  let counter = 1

  while (!(point.eq(pointPositive) || point.eq(pointNegative))) {
    pointPositive = pointPositive.add(startingPoint)
    pointNegative = pointNegative.add(startingPoint.neg())
    counter += 1
  }

  return point.eq(pointNegative) ? -counter : counter
}

export const tallyVotes = (pk: string, sk: BN, votes: ECCipher[]): number => {
  // This function is called in the fronend and did not work with
  // passing a curve.base.BasePoint directly before. It failed in
  // the encrypt function with 'red works only with red numbers'.

  // Fix: Serialize the key in the fronend and extract the public key from the passed hex-string
  const publicKey = curve25519.keyFromPublic(pk, 'hex').pub

  const sum = decrypt(addVotes(votes, publicKey), sk)
  return sum.eq(infinityPoint) ? 0 : findPoint(sum)
}

export const checkDecrypedSum = (decryptedSum: curve.base.BasePoint): number => {
  return decryptedSum.eq(infinityPoint) ? 0 : findPoint(decryptedSum)
}

export const getSummary = (total: number, tallyResult: number) => {
  let yes = 0
  let no = 0
  if (tallyResult === 0) {
    // total % 2 = 0
    yes = total / 2
    no = total / 2
  } else if (tallyResult < 0) {
    const diff = (total + tallyResult) / 2
    no = -1 * tallyResult + diff
    yes = total - no
  } else if (tallyResult > 0) {
    const diff = (total - tallyResult) / 2
    yes = tallyResult + diff
    no = total - yes
  }
  return { total, yes, no }
}

export function generateYesProof(encryptedVote: ECCipher, params: ECParamsTransfer, id: string): ValidVoteProof {
  const _params: ECParams = createParams(params)

  return VoteZKP.generateYesProof(encryptedVote, _params, id)
}

export const generateNoProof = (encryptedVote: ECCipher, params: ECParamsTransfer, id: string): ValidVoteProof => {
  const _params: ECParams = createParams(params)

  return VoteZKP.generateNoProof(encryptedVote, _params, id)
}

export const generateSumProof = (encryptedVote: ECCipher, params: ECParamsTransfer, sk: BN, id: string): SumProof => {
  const _params: ECParams = createParams(params)

  return SumZKP.generateSumProof(encryptedVote, _params, sk, id)
}

export const verifyZKP = (encryptedVote: ECCipher, proof: ValidVoteProof, params: ECParamsTransfer, id: string): boolean => {
  const _params: ECParams = createParams(params)

  return VoteZKP.verifyZKP(encryptedVote, proof, _params, id)
}

export const verifySumProof = (encryptedSum: ECCipher, proof: SumProof, params: ECParamsTransfer, pk: string, id: string): boolean => {
  const _params: ECParams = createParams(params)
  const publicKey = curve25519.keyFromPublic(pk, 'hex').pub

  return SumZKP.verifySumProof(encryptedSum, proof, _params, publicKey, id)
}

const createParams = (params: ECParamsTransfer): ECParams => {
  return {
    p: params.p, // BN
    n: params.n, // BN
    g: curve25519.curve.pointFromJSON(params.g), // string JSON
    h: curve25519.keyFromPublic(params.h, 'hex').pub, // string
  }
}
