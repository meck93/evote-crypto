import { encrypt, homomorphicAdd, decrypt } from './eccElgamal'
import { Cipher } from './models'

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
  let sum = encrypt(infinityPoint, publicKey) // zero vote

  for (const vote of votes) {
    sum = homomorphicAdd(sum, vote)
  }

  return sum
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

export const tallyVotes = (
  publicKey: any,
  sk: any,
  votes: Cipher[]
): number => {
  const sum = decrypt(addVotes(votes, publicKey), sk)
  return sum.eq(infinityPoint) ? 0 : findPoint(sum)
}
