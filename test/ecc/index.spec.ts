export {}
import { Cipher, EccElGamal, EccElGamalVoting } from '../../src/index'

const { assert } = require('chai')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

// fix constants for values 0 -> 2 and 1 -> 4
const M_0 = ec.curve.pointFromX(2)
const M_1 = ec.curve.pointFromX(4)

describe('ECC Elgamal', function() {
  it('Points to encode messages should lie on curve', function() {
    assert(ec.curve.validate(M_1) && ec.curve.validate(M_0))
  })

  it('Decrypted value is the same as the original message', function() {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const plaintextMessage = M_0
    const cipherText_0 = EccElGamal.encrypt(plaintextMessage, publicKey)
    const decryptedCipherText = EccElGamal.decrypt(cipherText_0, privateKey)

    assert(decryptedCipherText.eq(plaintextMessage))
  })

  it('Two added ciphertexts should be the same as adding two plain texts', function() {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const plaintextMessage0 = M_0
    const plaintextMessage1 = M_1

    const cipher0 = EccElGamal.encrypt(plaintextMessage0, publicKey)
    const cipher1 = EccElGamal.encrypt(plaintextMessage1, publicKey)

    const additiveCipher = EccElGamal.homomorphicAdd(cipher0, cipher1)

    const additivePlainText = EccElGamal.decrypt(additiveCipher, privateKey)

    assert(additivePlainText.eq(M_0.add(M_1)))
  })

  it('vote', () => {
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
