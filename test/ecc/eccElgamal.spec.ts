export {}

const { expect, assert } = require('chai')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const crypto = require('crypto')
const BN = require('bn.js')
const eccElgamal = require('../../src/ecc/eccElgamal.js')

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
})
