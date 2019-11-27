import { encrypt, decrypt } from './encryption'
import { Encryption, Helper, Curve } from './'
import { CurvePoint, Cipher } from './models'

import BN = require('bn.js')
import { Summary } from '../models'

const startingPoint = Curve.g
const infinityPoint = startingPoint.add(startingPoint.neg())

export const generateYesVote = (pk: string | CurvePoint): Cipher => {
  return encrypt(startingPoint, Helper.deserializeCurvePoint(pk))
}

export const generateNoVote = (pk: string | CurvePoint): Cipher => {
  return encrypt(startingPoint.neg(), Helper.deserializeCurvePoint(pk))
}

export const generateBaseVote = (pk: string | CurvePoint): Cipher => {
  return encrypt(infinityPoint, Helper.deserializeCurvePoint(pk))
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
  const publicKey = Helper.deserializeCurvePoint(pk)

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

