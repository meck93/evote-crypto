import { expect } from 'chai'
import { FFelGamal } from '../../src/index'

describe('Finite Field ElGamal Voting', () => {
  it('vote (0, 1, 2 voters)', () => {
    const vote = (_result: number, _votes: number[]): void => {
      const [sp, { h: pk, sk }] = FFelGamal.SystemSetup.generateSystemParametersAndKeys(1319, 2)

      const log = false

      const votes: FFelGamal.Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(FFelGamal.Voting.generateYesVote(sp, pk))
        vote === 0 && votes.push(FFelGamal.Voting.generateNoVote(sp, pk))
      }

      const result = FFelGamal.Voting.tallyVotes(sp, sk, votes)
      const summary = FFelGamal.Voting.getSummary(votes.length, result)
      log &&
        console.log(
          _result,
          _votes,
          result,
          'Total:',
          summary.total,
          '| Yes:',
          summary.yes,
          '| No:',
          summary.no
        )

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter((v) => v === 1).length)
      expect(summary.no).to.equal(_votes.filter((v) => v === 0).length)
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
  })

  it('vote (3 voters)', () => {
    const vote = (_result: number, _votes: number[]): void => {
      const [sp, { h: pk, sk }] = FFelGamal.SystemSetup.generateSystemParametersAndKeys(1319, 2)

      const log = false

      const votes: FFelGamal.Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(FFelGamal.Voting.generateYesVote(sp, pk))
        vote === 0 && votes.push(FFelGamal.Voting.generateNoVote(sp, pk))
      }

      const result = FFelGamal.Voting.tallyVotes(sp, sk, votes)
      const summary = FFelGamal.Voting.getSummary(votes.length, result)
      log &&
        console.log(
          _result,
          _votes,
          result,
          'Total:',
          summary.total,
          '| Yes:',
          summary.yes,
          '| No:',
          summary.no
        )

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter((v) => v === 1).length)
      expect(summary.no).to.equal(_votes.filter((v) => v === 0).length)
    }

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
  })

  it('vote (4 voters)', () => {
    const vote = (_result: number, _votes: number[]): void => {
      const [sp, { h: pk, sk }] = FFelGamal.SystemSetup.generateSystemParametersAndKeys(1319, 2)

      const log = false

      const votes: FFelGamal.Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(FFelGamal.Voting.generateYesVote(sp, pk))
        vote === 0 && votes.push(FFelGamal.Voting.generateNoVote(sp, pk))
      }

      const result = FFelGamal.Voting.tallyVotes(sp, sk, votes)
      const summary = FFelGamal.Voting.getSummary(votes.length, result)
      log &&
        console.log(
          _result,
          _votes,
          result,
          'Total:',
          summary.total,
          '| Yes:',
          summary.yes,
          '| No:',
          summary.no
        )

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter((v) => v === 1).length)
      expect(summary.no).to.equal(_votes.filter((v) => v === 0).length)
    }

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

  it('larger vote (20 voters, 48-bit prime modulo)', () => {
    const vote = (_result: number, _votes: number[]): void => {
      const [sp, { h: pk, sk }] = FFelGamal.SystemSetup.generateSystemParametersAndKeys(
        202178360940839,
        4
      )

      const log = false

      const votes: FFelGamal.Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(FFelGamal.Voting.generateYesVote(sp, pk))
        vote === 0 && votes.push(FFelGamal.Voting.generateNoVote(sp, pk))
      }

      const result = FFelGamal.Voting.tallyVotes(sp, sk, votes)
      const summary = FFelGamal.Voting.getSummary(votes.length, result)
      log &&
        console.log(
          _result,
          _votes,
          result,
          'Total:',
          summary.total,
          '| Yes:',
          summary.yes,
          '| No:',
          summary.no
        )

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter((v) => v === 1).length)
      expect(summary.no).to.equal(_votes.filter((v) => v === 0).length)
    }

    // voters: 20
    vote(10, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
  })
})
