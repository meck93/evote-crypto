import { encrypt, homomorphicAdd, decrypt } from './encryption'
import { Cipher } from '../models'

const EC = require('elliptic').ec
const ec = new EC('secp256k1')

const startingPoint = ec.curve.g
const infinityPoint = startingPoint.add(startingPoint.neg())

export const generateYesVote = (publicKey: any): any => {
  return encrypt(startingPoint, publicKey)
}

export const generateNoVote = (publicKey: any): any => {
  return encrypt(startingPoint.neg(), publicKey)
}

export const addVotes = (votes: Cipher[], publicKey: any): Cipher => {
  return votes.reduce((previous, current) => homomorphicAdd(previous, current), encrypt(infinityPoint, publicKey))
}

export const findPoint = (point: any): number => {
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

export const tallyVotes = (publicKey: any, sk: any, votes: Cipher[]): number => {
  const sum = decrypt(addVotes(votes, publicKey), sk)
  return sum.eq(infinityPoint) ? 0 : findPoint(sum)
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
