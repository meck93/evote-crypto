import { Summary } from '../index'
import { Cipher, Encryption, Helper, PublicKey } from './index'

import BN = require('bn.js')

export const generateYesVote = (pk: PublicKey): Cipher => Encryption.encrypt(1, pk)
export const generateNoVote = (pk: PublicKey): Cipher => Encryption.encrypt(0, pk)
export const generateBaseVote = (): Cipher => ({ a: Helper.newBN(1), b: Helper.newBN(1) }) // encrypt with m=0, r=0

export const addVotes = (votes: Cipher[], pk: PublicKey): Cipher => {
  return votes.reduce((previous, current) => Encryption.add(previous, current, pk), generateBaseVote())
}

export const tallyVotes = (pk: PublicKey, sk: BN, votes: Cipher[]): number => {
  return Encryption.decrypt1(addVotes(votes, pk), sk, pk).toNumber()
}

export const getSummary = (total: number, tallyResult: number): Summary => {
  const yes = tallyResult - 0
  const no = total - yes
  return { total, yes, no }
}
