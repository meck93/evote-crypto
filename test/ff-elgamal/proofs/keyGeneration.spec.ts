import { expect } from 'chai'
import { FFelGamal, GlobalHelper } from '../../../src/index'

describe('ElGamal Finite Field NIZKP for Key Generation', () => {
  it('generate and verify (distributed) key share', () => {
    for (let i = 0; i < 10; i++) {
      const log = false

      // generate the system parameters: P, Q, G
      const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)

      // generate the public and private key share: H_, SK_
      const share: FFelGamal.KeyPair = FFelGamal.SystemSetup.generateKeyPair(sp)
      expect(share.h.eq(sp.g.pow(share.sk).mod(sp.p))).to.be.true

      log && console.log('Key Parts')
      log && console.log('h:\t', share.h.toString())
      log && console.log('sk:\t', share.sk.toString())
      log && console.log()

      // generate the key share generation proof
      const uniqueId = 'IamReallyUnique;-)'
      const proof: FFelGamal.Proof.KeyGenerationProof = FFelGamal.Proof.KeyGeneration.generate(
        sp,
        share,
        uniqueId
      )
      const { c: c1, d: d1 } = proof

      log && console.log('Proof Parts')
      log && console.log('c:\t', c1.toString())
      log && console.log('d1:\t', d1.toString())
      log && console.log()

      // verify that the key share has been generated truthfully
      const verifiedProof: boolean = FFelGamal.Proof.KeyGeneration.verify(
        sp,
        proof,
        share.h,
        uniqueId
      )

      expect(verifiedProof).to.be.true
    }
  })

  it('perform distributed key generation', () => {
    const log = false

    const sp: FFelGamal.SystemParameters = FFelGamal.SystemSetup.generateSystemParameters(11, 3)

    // first authority
    // generate the public and private key share and the key generation proof
    const share1: FFelGamal.KeyPair = FFelGamal.SystemSetup.generateKeyPair(sp)
    const uniqueId1 = 'IamReallyUnique;-)'
    const proof1: FFelGamal.Proof.KeyGenerationProof = FFelGamal.Proof.KeyGeneration.generate(
      sp,
      share1,
      uniqueId1
    )
    expect(FFelGamal.Proof.KeyGeneration.verify(sp, proof1, share1.h, uniqueId1)).to.be.true

    // second authority
    // generate the public and private key share and the key generation proof
    const share2: FFelGamal.KeyPair = FFelGamal.SystemSetup.generateKeyPair(sp)
    const uniqueId2 = 'IamMuchMoreUnique_o.o'
    const proof2: FFelGamal.Proof.KeyGenerationProof = FFelGamal.Proof.KeyGeneration.generate(
      sp,
      share2,
      uniqueId2
    )
    expect(FFelGamal.Proof.KeyGeneration.verify(sp, proof2, share2.h, uniqueId2)).to.be.true

    log && console.log('1: pk, sk', share1.h.toNumber(), share1.sk.toNumber())
    log && console.log('2: pk, sk', share2.h.toNumber(), share2.sk.toNumber())

    // combined keys
    const publicKey = FFelGamal.SystemSetup.combinePublicKeys(sp, [share1.h, share2.h])
    const privateKey = FFelGamal.SystemSetup.combinePrivateKeys(sp, [share1.sk, share2.sk])

    log && console.log('pk', publicKey.toNumber())
    log && console.log('sk', privateKey.toNumber())

    // encrypt some message
    const plaintext = GlobalHelper.newBN(3)
    const cipherText = FFelGamal.Encryption.encrypt(plaintext, sp, publicKey)

    log && console.log('plaintext', plaintext.toNumber())
    log && console.log('cipherText (a,b)', cipherText.a.toNumber(), cipherText.b.toNumber())

    // decrypt shares
    const decShare1 = FFelGamal.Encryption.decryptShare(sp, cipherText, share1.sk)
    const decShare2 = FFelGamal.Encryption.decryptShare(sp, cipherText, share2.sk)

    log && console.log('ds1', decShare1.toNumber())
    log && console.log('ds2', decShare2.toNumber())

    // create proofs
    const decryptionProof1 = FFelGamal.Proof.Decryption.generate(
      cipherText,
      sp,
      share1.sk,
      uniqueId1
    )

    const decryptionProof2 = FFelGamal.Proof.Decryption.generate(
      cipherText,
      sp,
      share2.sk,
      uniqueId2
    )

    // verify proofs
    const verifiedProof1 = FFelGamal.Proof.Decryption.verify(
      cipherText,
      decryptionProof1,
      sp,
      share1.h,
      uniqueId1
    )
    const verifiedProof2 = FFelGamal.Proof.Decryption.verify(
      cipherText,
      decryptionProof2,
      sp,
      share2.h,
      uniqueId2
    )
    expect(verifiedProof1).to.be.true
    expect(verifiedProof2).to.be.true

    // finish decryption by combining decrypted shares
    const decFinal = FFelGamal.Encryption.combineDecryptedShares(sp, cipherText, [
      decShare1,
      decShare2,
    ])

    // decrypt with combined private key
    const d2 = FFelGamal.Encryption.decrypt2(cipherText, privateKey, sp)

    log && console.log('d', decFinal.toNumber())
    log && console.log('d2', d2.toNumber())

    expect(decFinal.toNumber()).to.eql(d2.toNumber())
    expect(decFinal.toNumber()).to.eql(plaintext.toNumber())
  })
})
