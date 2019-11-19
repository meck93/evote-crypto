import { encrypt, add, decrypt1 } from './encryption'
import { PublicKey } from './models'
import { Cipher } from '../models'
import { newBN } from './helper'

export const generateYesVote = (pk: PublicKey): Cipher => encrypt(1, pk)
export const generateNoVote = (pk: PublicKey): Cipher => encrypt(0, pk)
export const generateBaseVote = (): Cipher => ({ a: newBN(1), b: newBN(1) }) // encrypt with m=0, r=0

export const addVotes = (votes: Cipher[], pk: PublicKey): Cipher => {
  return votes.reduce((previous, current) => add(previous, current, pk), generateBaseVote())
}

export const tallyVotes = (pk: PublicKey, sk: any, votes: Cipher[]): number => {
  return decrypt1(addVotes(votes, pk), sk, pk).toNumber()
}

export const getSummary = (total: number, tallyResult: number) => {
  let yes = tallyResult - 0
  let no = total - yes
  return { total, yes, no }
}
