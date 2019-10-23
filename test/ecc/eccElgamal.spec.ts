import { Cipher } from '../../src/ecc/models'
import {
  generateYesVote,
  generateNoVote,
  tallyVotes,
} from '../../src/ecc/voting'
const BN = require('bn.js')
export {}

const { assert } = require('chai')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const eccElgamal = require('../../src/ecc/eccElgamal.ts')

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
    const cipherText_0 = eccElgamal.encrypt(plaintextMessage, publicKey)
    const decryptedCipherText = eccElgamal.decrypt(cipherText_0, privateKey)

    assert(decryptedCipherText.eq(plaintextMessage))
  })

  it('Two added ciphertexts should be the same as adding two plain texts', function() {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const plaintextMessage0 = M_0
    const plaintextMessage1 = M_1

    const cipher0 = eccElgamal.encrypt(plaintextMessage0, publicKey)
    const cipher1 = eccElgamal.encrypt(plaintextMessage1, publicKey)

    const additiveCipher = eccElgamal.homomorphicAdd(cipher0, cipher1)

    const additivePlainText = eccElgamal.decrypt(additiveCipher, privateKey)

    assert(additivePlainText.eq(M_0.add(M_1)))
  })

  it('vote', () => {
    const vote = (_result: number, _votes: number[]) => {
      const keyPair = ec.genKeyPair()
      const privateKey = keyPair.getPrivate()
      const publicKey = keyPair.getPublic()

      const votes: Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(generateYesVote(publicKey))
        vote === 0 && votes.push(generateNoVote(publicKey))
      }

      const result = tallyVotes(publicKey, privateKey, votes)
      console.log(_result, _votes, result)
      assert(result === _result)
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
