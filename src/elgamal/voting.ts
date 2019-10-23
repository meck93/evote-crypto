import { PublicKey, Cipher } from './models'
import { encrypt, add, decrypt1 } from '.'

// The message to be encrypted needs to be between 1 and p-1 (both inclusive).
// Because of that, a 'yes' vote is of value '2' and a 'no' vote of value '1'.
// After summing up all votes, the sum needs to be decreased by
// (i)  the value of the 'zeroVote'
// (ii) the number of votes

export const generateYesVote = (pk: PublicKey): Cipher => {
  return encrypt(2, pk)
}

export const generateNoVote = (pk: PublicKey): Cipher => {
  return encrypt(1, pk)
}

export const tallyVotes = (pk: PublicKey, sk: any, votes: Cipher[]) => {
  const zeroVote = generateNoVote(pk)

  let sum = zeroVote
  for (const vote of votes) {
    sum = add(sum, vote, pk)
  }

  let sumDecrypted = decrypt1(sum, sk, pk)

  // remove zeroVote
  sumDecrypted -= 1

  // decrease sum by the total number of voters
  sumDecrypted -= votes.length

  return sumDecrypted
}
