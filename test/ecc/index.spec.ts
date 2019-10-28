export {}
import { Cipher, EccElGamal, EccElGamalVoting } from '../../src/index'

const { assert } = require('chai')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

// Fixed values for testing purposes
// NO Vote:  mapped to integer 2
// YES Vote:  mapped to integer 4
const noVoteInt = 2
const yesVoteInt = 4

// Map/encode votes to points on the elliptic curve
const noVoteOnCurve = ec.curve.pointFromX(noVoteInt)
const yesVoteOnCurve = ec.curve.pointFromX(yesVoteInt)

describe('EccElGamal Library Tests', function() {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(ec.curve.validate(yesVoteOnCurve) && ec.curve.validate(noVoteOnCurve))
  })

  it('Decrypted value is the same as the original message', function() {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const messageToEncrypt = noVoteOnCurve
    const cipherText = EccElGamal.encrypt(noVoteOnCurve, publicKey)
    const decryptedCipherText = EccElGamal.decrypt(cipherText, privateKey)

    assert(decryptedCipherText.eq(messageToEncrypt))
  })

  it('Two added ciphertexts should be the same as adding two plain texts', function() {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const voteToEncrypt0 = noVoteOnCurve
    const voteToEncrypt1 = yesVoteOnCurve

    const cipher0 = EccElGamal.encrypt(voteToEncrypt0, publicKey)
    const cipher1 = EccElGamal.encrypt(voteToEncrypt1, publicKey)

    const cipherHomomorphicSum = EccElGamal.homomorphicAdd(cipher0, cipher1)

    const decryptedHomomorphicSum = EccElGamal.decrypt(cipherHomomorphicSum, privateKey)

    assert(decryptedHomomorphicSum.eq(noVoteOnCurve.add(yesVoteOnCurve)))
  })
})

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
