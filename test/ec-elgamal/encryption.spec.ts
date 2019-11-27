export {}
import { ECelGamal } from '../../src/index'

const { assert } = require('chai')

// Fixed values for testing purposes
// NO Vote:  mapped to integer 3
// YES Vote:  mapped to integer 6
const noVoteInt = 3
const yesVoteInt = 6

// Map/encode votes to points on the elliptic curve
const noVoteOnCurve = ECelGamal.Curve.pointFromX(noVoteInt)
const yesVoteOnCurve = ECelGamal.Curve.pointFromX(yesVoteInt)

describe('Elliptic Curve ElGamal Encryption', function() {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(ECelGamal.Curve.validate(yesVoteOnCurve) && ECelGamal.Curve.validate(noVoteOnCurve))
  })

  it('Decrypted value is the same as the original message', function() {
    const {h: publicKey, sk: privateKey} = ECelGamal.SystemSetup.generateKeyPair()

    const messageToEncrypt = noVoteOnCurve
    const cipherText = ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey)
    const decryptedCipherText = ECelGamal.Encryption.decrypt(cipherText, privateKey)

    assert(decryptedCipherText.eq(messageToEncrypt))
  })

  it('Two added ciphertexts should be the same as adding two plain texts', function() {
    const {h: publicKey, sk: privateKey} = ECelGamal.SystemSetup.generateKeyPair()

    const voteToEncrypt0 = noVoteOnCurve
    const voteToEncrypt1 = yesVoteOnCurve

    const cipher0 = ECelGamal.Encryption.encrypt(voteToEncrypt0, publicKey)
    const cipher1 = ECelGamal.Encryption.encrypt(voteToEncrypt1, publicKey)

    const cipherHomomorphicSum = ECelGamal.Encryption.homomorphicAdd(cipher0, cipher1)

    const decryptedHomomorphicSum = ECelGamal.Encryption.decrypt(cipherHomomorphicSum, privateKey)

    assert(decryptedHomomorphicSum.eq(noVoteOnCurve.add(yesVoteOnCurve)))
  })
})
