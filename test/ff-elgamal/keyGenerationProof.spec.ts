export {}
import { FFelGamal } from '../../src/index'
import { newBN } from '../../src/ff-elgamal/helper'
import { expect } from 'chai'

describe('ElGamal Finite Field NIZKP for Key Generation', () => {
  it('generate and verify (distributed) key share', () => {
    for (let i = 0; i < 10; i++) {
      const prnt = false

      // generate the system parameters: P, Q, G
      const sp: FFelGamal.SystemParameters = FFelGamal.Encryption.generateSystemParameters(11, 3)

      // generate the public and private key share: H_, SK_
      const share: FFelGamal.KeyPair = FFelGamal.Encryption.generateKeyPair(sp)

      expect(share.h).to.eql(sp.g.pow(share.sk).mod(sp.p))

      prnt && console.log('Key Parts')
      prnt && console.log('h:\t', share.h.toString())
      prnt && console.log('sk:\t', share.sk.toString())
      prnt && console.log()

      // generate the key share generation proof
      const uniqueId = 'IamReallyUnique;-)'
      const proof: FFelGamal.KeyShareProof = FFelGamal.KeyGenerationProof.generate(
        sp,
        share,
        uniqueId
      )
      const { c: c1, d: d1 } = proof

      prnt && console.log('Proof Parts')
      prnt && console.log('c:\t', c1.toString())
      prnt && console.log('d1:\t', d1.toString())
      prnt && console.log()

      // verify that the key share has been generated truthfully
      const verifiedProof: boolean = FFelGamal.KeyGenerationProof.verify(
        sp,
        proof,
        share.h,
        uniqueId
      )

      expect(verifiedProof).to.be.true
    }
  })

  it('combine public keys', () => {
    const sp: FFelGamal.SystemParameters = FFelGamal.Encryption.generateSystemParameters(11, 3)

    let shares = [newBN(1)]
    let product = 1
    expect(FFelGamal.KeyGenerationProof.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [newBN(4), newBN(2)]
    product = 8
    expect(FFelGamal.KeyGenerationProof.combinePublicKeys(sp, shares).toNumber()).to.eql(product)

    shares = [newBN(2), newBN(3), newBN(4)]
    product = 2
    expect(FFelGamal.KeyGenerationProof.combinePublicKeys(sp, shares).toNumber()).to.eql(product)
  })

  it('perform distributed key generation', () => {
    const prnt = false

    const sp: FFelGamal.SystemParameters = FFelGamal.Encryption.generateSystemParameters(11, 3)

    // first authority
    // generate the public and private key share and the key generation proof
    const share1: FFelGamal.KeyPair = FFelGamal.Encryption.generateKeyPair(sp)
    const uniqueId1 = 'IamReallyUnique;-)'
    const proof1: FFelGamal.KeyShareProof = FFelGamal.KeyGenerationProof.generate(
      sp,
      share1,
      uniqueId1
    )
    expect(FFelGamal.KeyGenerationProof.verify(sp, proof1, share1.h, uniqueId1)).to.be
      .true

    // second authority
    // generate the public and private key share and the key generation proof
    const share2: FFelGamal.KeyPair = FFelGamal.Encryption.generateKeyPair(sp)
    const uniqueId2 = 'IamMuchMoreUnique_o.o'
    const proof2: FFelGamal.KeyShareProof = FFelGamal.KeyGenerationProof.generate(
      sp,
      share2,
      uniqueId2
    )
    expect(FFelGamal.KeyGenerationProof.verify(sp, proof2, share2.h, uniqueId2)).to.be
      .true

    prnt && console.log('1: pk, sk', share1.h.toNumber(), share1.sk.toNumber())
    prnt && console.log('2: pk, sk', share2.h.toNumber(), share2.sk.toNumber())

    // combined keys
    const publicKey = FFelGamal.KeyGenerationProof.combinePublicKeys(sp, [share1.h, share2.h])
    const privateKey = FFelGamal.KeyGenerationProof.combinePrivateKeys(sp, [share1.sk, share2.sk])

    prnt && console.log('pk', publicKey.toNumber())
    prnt && console.log('sk', privateKey.toNumber())

    // encrypt some message
    const plaintext = newBN(3)
    const cipherText = FFelGamal.Encryption.encrypt(plaintext, sp, publicKey)

    prnt && console.log('plaintext', plaintext.toNumber())
    prnt && console.log('cipherText (a,b)', cipherText.a.toNumber(), cipherText.b.toNumber())

    // decrypt shares
    const decShare1 = FFelGamal.KeyGenerationProof.decryptShare(sp, cipherText, share1.sk)
    const decShare2 = FFelGamal.KeyGenerationProof.decryptShare(sp, cipherText, share2.sk)

    prnt && console.log('ds1', decShare1.toNumber())
    prnt && console.log('ds2', decShare2.toNumber())

    // create proofs
    const decryptionProof1 = FFelGamal.DecryptionProof.generate(
      cipherText,
      sp,
      share1.sk,
      uniqueId1
    )

    const decryptionProof2 = FFelGamal.DecryptionProof.generate(
      cipherText,
      sp,
      share2.sk,
      uniqueId2
    )

    // verify proofs
    const verifiedProof1 = FFelGamal.DecryptionProof.verify(
      cipherText,
      decryptionProof1,
      sp,
      share1.h,
      uniqueId1
    )
    const verifiedProof2 = FFelGamal.DecryptionProof.verify(
      cipherText,
      decryptionProof2,
      sp,
      share2.h,
      uniqueId2
    )
    expect(verifiedProof1).to.be.true
    expect(verifiedProof2).to.be.true

    // finish decryption by combining decrypted shares
    const decFinal = FFelGamal.KeyGenerationProof.combineDecryptedShares(sp, cipherText, [
      decShare1,
      decShare2,
    ])

    // decrypt with combined private key
    const d2 = FFelGamal.Encryption.decrypt2(cipherText, privateKey, sp)

    prnt && console.log('d', decFinal.toNumber())
    prnt && console.log('d2', d2.toNumber())

    expect(decFinal.toNumber()).to.eql(d2.toNumber())
    expect(decFinal.toNumber()).to.eql(plaintext.toNumber())
  })
})
