import { encrypt, add, decrypt1 } from '.'
import { PublicKey } from './models'
import { Cipher } from '../models'

export const generateYesVote = (pk: PublicKey): Cipher => {
  return encrypt(1, pk)
}

export const generateNoVote = (pk: PublicKey): Cipher => {
  return encrypt(0, pk)
}

export const addVotes = (votes: Cipher[], pk: PublicKey): Cipher => {
  let sum = generateNoVote(pk) // zero vote

  for (const vote of votes) {
    sum = add(sum, vote, pk)
  }

  return sum
}

export const tallyVotes = (pk: PublicKey, sk: any, votes: Cipher[]): number => {
  let sum = decrypt1(addVotes(votes, pk), sk, pk).toNumber()

  return sum
}

export const getSummary = (total: number, tallyResult: number) => {
  let yes = tallyResult
  let no = total - yes
  return { total, yes, no }
}
