import { Summary } from '../index'
import { Cipher, Encryption, Helper, SystemParameters } from './index'

import BN = require('bn.js')

export const generateYesVote = (sp: SystemParameters, pk: BN): Cipher =>
  Encryption.encrypt(1, sp, pk)
export const generateNoVote = (sp: SystemParameters, pk: BN): Cipher =>
  Encryption.encrypt(0, sp, pk)
export const generateBaseVote = (): Cipher => {
  return { a: Helper.newBN(1), b: Helper.newBN(1) }
} // encrypt with m=0, r=0

export const addVotes = (votes: Cipher[], sp: SystemParameters): Cipher => {
  return votes.reduce(
    (previous, current) => Encryption.add(previous, current, sp),
    generateBaseVote()
  )
}

export const tallyVotes = (sp: SystemParameters, sk: BN, votes: Cipher[]): number => {
  return Encryption.decrypt1(addVotes(votes, sp), sk, sp).toNumber()
}

export const getSummary = (total: number, tallyResult: number): Summary => {
  const yes = tallyResult - 0
  const no = total - yes
  return { total, yes, no }
}
