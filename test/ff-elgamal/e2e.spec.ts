export {}
import { Cipher, FFelGamal, ValidVoteProof } from '../../src/index'

const random = require('random')
const { expect } = require('chai')
const web3 = require('web3')

describe('ElGamal Finite Field E2E Test', () => {
  it('complete vote', () => {
    const vote = (p: number, g: number, _result: number, _votes: number[]) => {
      const baseID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'
      const govID = 'GOV_ID_SUPER_SECURE_:-)'

      const prnt = false
      prnt && console.log('p:', p, 'q:', (p - 1) / 2, 'g:', g)

      let pk
      let sk

      try {
        ;[pk, sk] = FFelGamal.Encryption.generateKeys(p, g)
      } catch (error) {
        console.error(error)
      }

      const votes: Cipher[] = []

      // generate votes and proofs with random IDs
      for (const vote of _votes) {
        const id = web3.utils.soliditySha3(random.int(1, Math.pow(2, 16)))

        if (vote === 1) {
          const encYesVote = FFelGamal.Voting.generateYesVote(pk)
          votes.push(encYesVote)

          const encYesProof = FFelGamal.VoteZKP.generateYesProof(encYesVote, pk, id)

          const validVote = FFelGamal.VoteZKP.verifyVoteProof(encYesVote, encYesProof, pk, id)
          expect(validVote).to.be.true
        } else {
          const encNoVote = FFelGamal.Voting.generateNoVote(pk)
          votes.push(encNoVote)

          const encNoProof = FFelGamal.VoteZKP.generateNoProof(encNoVote, pk, id)

          const validVote = FFelGamal.VoteZKP.verifyVoteProof(encNoVote, encNoProof, pk, id)
          expect(validVote).to.be.true
        }
      }

      // homomorphically add all votes and create sum proof
      const encryptedSum = FFelGamal.Voting.addVotes(votes, pk)
      const sumProof = FFelGamal.SumZKP.generateSumProof(encryptedSum, pk, sk, govID)

      // verifiy the sum proof
      const validSum = FFelGamal.SumZKP.verifySumProof(encryptedSum, sumProof, pk, govID)
      expect(validSum).to.be.true

      // decrypt the sum
      const decryptedSum = FFelGamal.Encryption.decrypt1(encryptedSum, sk, pk)
      const summary = FFelGamal.Voting.getSummary(votes.length, decryptedSum)
      prnt && console.log(_result, _votes, 'Total:', summary.total, '| Yes:', summary.yes, '| No:', summary.no)

      expect(decryptedSum.toNumber()).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter(v => v === 1).length)
      expect(summary.no).to.equal(_votes.filter(v => v === 0).length)
    }

    // voters: 3
    // result: 2 yes, 1 no
    // p = 23, q = 11, g = 2
    vote(23, 2, 2, [1, 1, 0])

    // voters: 26
    // result: 17 yes, 9 no
    // p = 107, q = 53, g = 3
    vote(107, 3, 17, [1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1])
  })
})
