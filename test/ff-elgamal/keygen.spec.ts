export {}
import { FFelGamal } from '../../src/index'
import { KeyShareProof } from '../../src/models'
import { newBN } from '../../src/ff-elgamal/helper'
import { PublicKey } from '../../src/ff-elgamal'

const { expect } = require('chai')

describe('Finite Field ElGamal Distributed Key Generation', () => {
  it('generate and verify (distributed) key share', () => {
    for (let i = 0; i < 10; i++) {
      const prnt = false
      const p_: number = 11
      const q_: number = (p_ - 1) / 2
      const g_: number = 3

      // generate the system parameters: P, Q, G
      const params: FFelGamal.SystemParameters = FFelGamal.KeyGeneration.generateSystemParameters(p_, q_, g_)
      const { p, q, g } = params

      // generate the public and private key share: H_, SK_
      const share: FFelGamal.KeyShare = FFelGamal.KeyGeneration.generateKeyShares(params)
      const { h_: h1_, sk_: sk1_ } = share

      expect(h1_).to.eql(g.pow(sk1_).mod(p))

      prnt && console.log('Key Parts')
      prnt && console.log('h_:\t', h1_.toString())
      prnt && console.log('sk_:\t', sk1_.toString())
      prnt && console.log()

      // generate the key share generation proof
      const uniqueId = 'IamReallyUnique;-)'
      const proof: KeyShareProof = FFelGamal.KeyGeneration.generateKeyGenerationProof(params, share, uniqueId)
      const { c: c1, d: d1 } = proof

      prnt && console.log('Proof Parts')
      prnt && console.log('c:\t', c1.toString())
      prnt && console.log('d1:\t', d1.toString())
      prnt && console.log()

      // verify that the key share has been generated truthfully
      const verifiedProof: boolean = FFelGamal.KeyGeneration.verifyKeyGenerationProof(params, proof, h1_, uniqueId)

      expect(verifiedProof).to.be.true
    }
  })

  it('combine public keys', () => {
    const p_: number = 11
    const q_: number = (p_ - 1) / 2
    const g_: number = 3
    const params: FFelGamal.SystemParameters = FFelGamal.KeyGeneration.generateSystemParameters(p_, q_, g_)

    let shares = [newBN(1)]
    let product = 1
    expect(FFelGamal.KeyGeneration.combinePublicKeys(params, shares).toNumber()).to.eql(product)

    shares = [newBN(4), newBN(2)]
    product = 8
    expect(FFelGamal.KeyGeneration.combinePublicKeys(params, shares).toNumber()).to.eql(product)

    shares = [newBN(2), newBN(3), newBN(4)]
    product = 2
    expect(FFelGamal.KeyGeneration.combinePublicKeys(params, shares).toNumber()).to.eql(product)
  })

  it('perform distributed key generation', () => {
    const prnt = false
    const p_: number = 11
    const q_: number = (p_ - 1) / 2
    const g_: number = 3

    const params: FFelGamal.SystemParameters = FFelGamal.KeyGeneration.generateSystemParameters(p_, q_, g_)

    // first authority
    // generate the public and private key share and the key generation proof
    const share1: FFelGamal.KeyShare = FFelGamal.KeyGeneration.generateKeyShares(params)
    const uniqueId1 = 'IamReallyUnique;-)'
    const proof1: KeyShareProof = FFelGamal.KeyGeneration.generateKeyGenerationProof(params, share1, uniqueId1)
    expect(FFelGamal.KeyGeneration.verifyKeyGenerationProof(params, proof1, share1.h_, uniqueId1)).to.be.true

    // second authority
    // generate the public and private key share and the key generation proof
    const share2: FFelGamal.KeyShare = FFelGamal.KeyGeneration.generateKeyShares(params)
    const uniqueId2 = 'IamMuchMoreUnique_o.o'
    const proof2: KeyShareProof = FFelGamal.KeyGeneration.generateKeyGenerationProof(params, share2, uniqueId2)
    expect(FFelGamal.KeyGeneration.verifyKeyGenerationProof(params, proof2, share2.h_, uniqueId2)).to.be.true

    prnt && console.log('1: pk, sk', share1.h_.toNumber(), share1.sk_.toNumber())
    prnt && console.log('2: pk, sk', share2.h_.toNumber(), share2.sk_.toNumber())

    // combined keys
    const publicKey = FFelGamal.KeyGeneration.combinePublicKeys(params, [share1.h_, share2.h_])
    const privateKey = FFelGamal.KeyGeneration.combinePrivateKeys(params, [share1.sk_, share2.sk_])

    prnt && console.log('pk', publicKey.toNumber())
    prnt && console.log('sk', privateKey.toNumber())

    // TODO: adjust encryption implementation (PublicKey Interface)
    const encPubKey: PublicKey = { p: params.p, q: params.q, g: params.g, h: publicKey }

    // encrypt some message
    const plaintext = newBN(3)
    const cipherText = FFelGamal.Encryption.encrypt(plaintext, encPubKey)

    prnt && console.log('plaintext', plaintext.toNumber())
    prnt && console.log('cipherText (a,b)', cipherText.a.toNumber(), cipherText.b.toNumber())

    // decrypt shares
    const decShare1 = FFelGamal.KeyGeneration.decryptShare(params, cipherText, share1.sk_)
    const decShare2 = FFelGamal.KeyGeneration.decryptShare(params, cipherText, share2.sk_)

    prnt && console.log('ds1', decShare1.toNumber())
    prnt && console.log('ds2', decShare2.toNumber())

    // finish decryption by combining decrypted shares
    const decFinal = FFelGamal.KeyGeneration.combineDecryptedShares(params, cipherText, [decShare1, decShare2])

    // decrypt with combined private key
    const d2 = FFelGamal.Encryption.decrypt2(cipherText, privateKey, encPubKey)

    prnt && console.log('d', decFinal.toNumber())
    prnt && console.log('d2', d2.toNumber())

    expect(decFinal.toNumber()).to.eql(d2.toNumber())
    expect(decFinal.toNumber()).to.eql(plaintext.toNumber())
  })
})
