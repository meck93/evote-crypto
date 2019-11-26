import { encrypt, decrypt } from './encryption'
import { VoteZKP, Encryption } from './'
import { ECParams, ECParamsTransfer, CurvePoint, Cipher, ValidVoteProof } from './models'

import BN = require('bn.js')
import { Summary } from '../models'

import { activeCurve } from './activeCurve'

const startingPoint = activeCurve.curve.g
const infinityPoint = startingPoint.add(startingPoint.neg())

const pkToCurvePoint = (pk: string | CurvePoint): CurvePoint => {
  if (typeof pk === 'string' || pk instanceof String) {
    return activeCurve.keyFromPublic(pk, 'hex').pub
  } else {
    return pk
  }
}

export const generateYesVote = (pk: string | CurvePoint): Cipher => {
  return encrypt(startingPoint, pkToCurvePoint(pk))
}

export const generateNoVote = (pk: string | CurvePoint): Cipher => {
  return encrypt(startingPoint.neg(), pkToCurvePoint(pk))
}

export const generateBaseVote = (pk: string | CurvePoint): Cipher => {
  return encrypt(infinityPoint, pkToCurvePoint(pk))
}

export const addVotes = (votes: Cipher[], pk: string | CurvePoint): Cipher => {
  return votes.reduce(
    (previous, current) => Encryption.homomorphicAdd(previous, current),
    generateBaseVote(pk)
  )
}

export const findPoint = (point: CurvePoint): number => {
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

export const tallyVotes = (pk: string, sk: BN, votes: Cipher[]): number => {
  // This function is called in the fronend and did not work with
  // passing a CurvePoint directly before. It failed in
  // the encrypt function with 'red works only with red numbers'.

  // Fix: Serialize the key in the fronend and extract the public key from the passed hex-string
  const publicKey = pkToCurvePoint(pk)

  const sum = decrypt(addVotes(votes, publicKey), sk)
  return checkDecrypedSum(sum)
}

export const checkDecrypedSum = (decryptedSum: CurvePoint): number => {
  return decryptedSum.eq(infinityPoint) ? 0 : findPoint(decryptedSum)
}

export const getSummary = (total: number, tallyResult: number): Summary => {
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
  return { total, yes, no } as Summary
}

const createParams = (params: ECParamsTransfer): ECParams => {
  return {
    p: params.p, // BN
    n: params.n, // BN
    g: activeCurve.curve.pointFromJSON(params.g), // string JSON
    h: activeCurve.keyFromPublic(params.h, 'hex').pub, // string
  }
}

export function generateYesProof(
  encryptedVote: Cipher,
  params: ECParamsTransfer,
  id: string
): ValidVoteProof {
  const _params: ECParams = createParams(params)

  return VoteZKP.generateYesProof(encryptedVote, _params, id)
}

export const generateNoProof = (
  encryptedVote: Cipher,
  params: ECParamsTransfer,
  id: string
): ValidVoteProof => {
  const _params: ECParams = createParams(params)

  return VoteZKP.generateNoProof(encryptedVote, _params, id)
}

export const verifyZKP = (
  encryptedVote: Cipher,
  proof: ValidVoteProof,
  params: ECParamsTransfer,
  id: string
): boolean => {
  const _params: ECParams = createParams(params)

  return VoteZKP.verifyZKP(encryptedVote, proof, _params, id)
}
