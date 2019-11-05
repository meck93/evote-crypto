export {}
import { EccElGamal } from '../../src/index'

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
