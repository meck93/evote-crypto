export { }
import { ECelGamal } from '../../src/index'

const { expect, assert } = require('chai')
const EC = require('elliptic').ec
const ec = new EC('curve25519-weier')

// Fixed values for testing purposes
// NO Vote:  mapped to integer 3
// YES Vote:  mapped to integer 6
const noVoteInt = 3
const yesVoteInt = 6

// Map/encode votes to points on the elliptic curve
const noVoteOnCurve = ec.curve.pointFromX(noVoteInt)
const yesVoteOnCurve = ec.curve.pointFromX(yesVoteInt)

describe('Elliptic Curve ElGamal Encryption', function () {
  it('Points that encode the plaintexts should lie on the curve', function () {
    assert(ec.curve.validate(yesVoteOnCurve) && ec.curve.validate(noVoteOnCurve))
  })

  it('Decrypted value is the same as the original message', function () {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const messageToEncrypt = noVoteOnCurve
    const cipherText = ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey)
    const decryptedCipherText = ECelGamal.Encryption.decrypt(cipherText, privateKey)

    assert(decryptedCipherText.eq(messageToEncrypt))
  })

  it('Two added ciphertexts should be the same as adding two plain texts', function () {
    const keyPair = ec.genKeyPair()
    const privateKey = keyPair.getPrivate()
    const publicKey = keyPair.getPublic()

    const voteToEncrypt0 = noVoteOnCurve
    const voteToEncrypt1 = yesVoteOnCurve

    const cipher0 = ECelGamal.Encryption.encrypt(voteToEncrypt0, publicKey)
    const cipher1 = ECelGamal.Encryption.encrypt(voteToEncrypt1, publicKey)

    const cipherHomomorphicSum = ECelGamal.Encryption.homomorphicAdd(cipher0, cipher1)

    const decryptedHomomorphicSum = ECelGamal.Encryption.decrypt(cipherHomomorphicSum, privateKey)

    assert(decryptedHomomorphicSum.eq(noVoteOnCurve.add(yesVoteOnCurve)))
  })
})
