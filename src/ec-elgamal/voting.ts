import { encrypt, homomorphicAdd, decrypt } from './encryption'
import { ECCipher } from './models'
import { curve } from 'elliptic'

import BN = require('bn.js')

const EC = require('elliptic').ec
const secp256k1 = new EC('secp256k1')

const startingPoint = secp256k1.curve.g
const infinityPoint = startingPoint.add(startingPoint.neg())

export const generateYesVote = (publicKey: curve.base.BasePoint): ECCipher => {
  return encrypt(startingPoint, publicKey)
}

export const generateNoVote = (publicKey: curve.base.BasePoint): ECCipher => {
  return encrypt(startingPoint.neg(), publicKey)
}

export const addVotes = (votes: ECCipher[], publicKey: any): ECCipher => {
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

export const tallyVotes = (publicKey: curve.base.BasePoint, sk: BN, votes: ECCipher[]): number => {
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
