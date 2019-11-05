export {}
import { Cipher, FFelGamal } from '../../src/index'

const { expect } = require('chai')

describe('Finite Field ElGamal Voting', () => {
  it('vote', () => {
    const vote = (_result: number, _votes: number[]) => {
      const [pk, sk] = FFelGamal.Encryption.generateKeys(137, 51)

      const votes: Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(FFelGamal.Voting.generateYesVote(pk))
        vote === 0 && votes.push(FFelGamal.Voting.generateNoVote(pk))
      }

      const result = FFelGamal.Voting.tallyVotes(pk, sk, votes)
      const summary = FFelGamal.Voting.getSummary(votes.length, result)
      console.log(_result, _votes, result, 'Total:', summary.total, '| Yes:', summary.yes, '| No:', summary.no)

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter(v => v === 1).length)
      expect(summary.no).to.equal(_votes.filter(v => v === 0).length)
    }

    // voters:  0
    // results: 2^0 = 1
    vote(0, [])

    // voters:  1
    // results: 2^1 = 2
    vote(0, [0])
    vote(1, [1])

    // voters:  2
    // results: 2^2 = 4
    vote(0, [0, 0])
    vote(1, [0, 1])
    vote(1, [1, 0])
    vote(2, [1, 1])

    // voters:  3
    // results: 2^3 = 8
    vote(0, [0, 0, 0])
    vote(1, [0, 0, 1])
    vote(1, [0, 1, 0])
    vote(2, [0, 1, 1])
    vote(1, [1, 0, 0])
    vote(2, [1, 0, 1])
    vote(2, [1, 1, 0])
    vote(3, [1, 1, 1])

    // voters:  4
    // results: 2^4 = 16
    vote(0, [0, 0, 0, 0])
    vote(1, [0, 0, 0, 1])
    vote(1, [0, 0, 1, 0])
    vote(2, [0, 0, 1, 1])
    vote(1, [0, 1, 0, 0])
    vote(2, [0, 1, 0, 1])
    vote(2, [0, 1, 1, 0])
    vote(3, [0, 1, 1, 1])
    vote(1, [1, 0, 0, 0])
    vote(2, [1, 0, 0, 1])
    vote(2, [1, 0, 1, 0])
    vote(3, [1, 0, 1, 1])
    vote(2, [1, 1, 0, 0])
    vote(3, [1, 1, 0, 1])
    vote(3, [1, 1, 1, 0])
    vote(4, [1, 1, 1, 1])
  })
})
