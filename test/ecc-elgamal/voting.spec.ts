export {}
import { Cipher, EccElGamalVoting } from '../../src/index'

const { assert } = require('chai')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

describe('EccElGamal Voting Tests', () => {
  it('Voting works correctly in various scenarii', () => {
    const vote = (_result: number, _votes: number[]) => {
      const keyPair = ec.genKeyPair()
      const privateKey = keyPair.getPrivate()
      const publicKey = keyPair.getPublic()

      const votes: Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(EccElGamalVoting.generateYesVote(publicKey))
        vote === 0 && votes.push(EccElGamalVoting.generateNoVote(publicKey))
      }

      const result = EccElGamalVoting.tallyVotes(publicKey, privateKey, votes)
      const summary = EccElGamalVoting.getSummary(votes.length, result)
      console.log(_result, _votes, result, 'Total:', summary.total, '| Yes:', summary.yes, '| No:', summary.no)

      assert(result === _result)
      assert(summary.yes === _votes.filter(v => v === 1).length)
      assert(summary.no === _votes.filter(v => v === 0).length)
    }

    // voters:  0
    // results: 2^0 = 1
    vote(0, [])

    // voters:  1
    // results: 2^1 = 2
    vote(-1, [0])
    vote(1, [1])

    // voters:  2
    // results: 2^2 = 4
    vote(-2, [0, 0])
    vote(0, [0, 1])
    vote(0, [1, 0])
    vote(2, [1, 1])

    // voters:  3
    // results: 2^3 = 8
    vote(-3, [0, 0, 0])
    vote(-1, [0, 0, 1])
    vote(-1, [0, 1, 0])
    vote(1, [0, 1, 1])
    vote(-1, [1, 0, 0])
    vote(1, [1, 0, 1])
    vote(1, [1, 1, 0])
    vote(3, [1, 1, 1])

    // voters:  4
    // results: 2^4 = 16
    vote(-4, [0, 0, 0, 0])
    vote(-2, [0, 0, 0, 1])
    vote(-2, [0, 0, 1, 0])
    vote(0, [0, 0, 1, 1])
    vote(-2, [0, 1, 0, 0])
    vote(0, [0, 1, 0, 1])
    vote(0, [0, 1, 1, 0])
    vote(2, [0, 1, 1, 1])
    vote(-2, [1, 0, 0, 0])
    vote(0, [1, 0, 0, 1])
    vote(0, [1, 0, 1, 0])
    vote(2, [1, 0, 1, 1])
    vote(0, [1, 1, 0, 0])
    vote(2, [1, 1, 0, 1])
    vote(2, [1, 1, 1, 0])
    vote(4, [1, 1, 1, 1])
  })
})
