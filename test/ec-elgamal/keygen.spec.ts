export {}
import { ECelGamal } from '../../src/index'
import { ECpow, ECmul } from '../../src/ec-elgamal/helper'

import { expect } from 'chai'
import { ec } from 'elliptic'
import { activeCurve } from '../../src/ec-elgamal/activeCurve'
import { CurvePoint, KeyShareProof } from '../../src/ec-elgamal/models'

describe('Elliptic Curve ElGamal Distributed Key Generation', () => {
  it('generate and verify (distributed) key share', () => {
    for (let i = 0; i < 10; i++) {
      const prnt = true

      // generate the system parameters: P, Q, G
      const params: ECelGamal.SystemParameters = ECelGamal.KeyGeneration.generateSystemParameters()
      const { g } = params

      // generate the public and private key share: H_, SK_
      const share: ECelGamal.KeyShare = ECelGamal.KeyGeneration.generateKeyShares()
      const { h_: h1_, sk_: sk1_ } = share

      expect(h1_).to.eql(ECpow(g, sk1_))

      prnt && console.log('Key Parts')
      prnt && console.log('h_:\t', h1_.toString())
      prnt && console.log('sk_:\t', sk1_.toString())
      prnt && console.log()

      // generate the key share generation proof
      const uniqueId = 'IamReallyUnique;-)'
      const proof: KeyShareProof = ECelGamal.KeyGeneration.generateKeyGenerationProof(params, share, uniqueId)
      const { c: c1, d: d1 } = proof

      prnt && console.log('Proof Parts')
      prnt && console.log('c:\t', c1.toString())
      prnt && console.log('d1:\t', d1.toString())
      prnt && console.log()

      // verify that the key share has been generated truthfully
      const verifiedProof: boolean = ECelGamal.KeyGeneration.verifyKeyGenerationProof(params, proof, h1_, uniqueId)

      expect(verifiedProof).to.be.true
    }
  })

  it('combine public keys', () => {
    // generate one share
    let keyPairs: ec.KeyPair[] = ECelGamal.KeyGeneration.generateKeyPairs(1)
    let shares: CurvePoint[] = [keyPairs[0].getPublic() as CurvePoint]
    let product: CurvePoint = shares[0]
    expect(ECelGamal.KeyGeneration.combinePublicKeys(shares)).to.eql(product)

    // generate two shares + combine them
    keyPairs = ECelGamal.KeyGeneration.generateKeyPairs(2)
    shares = [keyPairs[0].getPublic() as CurvePoint, keyPairs[1].getPublic() as CurvePoint]
    product = ECmul(shares[0], shares[1])
    expect(ECelGamal.KeyGeneration.combinePublicKeys(shares)).to.eql(product)

    // generate three shares + combine them
    keyPairs = ECelGamal.KeyGeneration.generateKeyPairs(3)
    shares = [keyPairs[0].getPublic() as CurvePoint, keyPairs[1].getPublic() as CurvePoint, keyPairs[2].getPublic() as CurvePoint]
    product = ECmul(ECmul(shares[0], shares[1]), shares[2])
    expect(ECelGamal.KeyGeneration.combinePublicKeys(shares)).to.eql(product)
  })

  it('perform distributed key generation', () => {
    const prnt = false

    const params: ECelGamal.SystemParameters = ECelGamal.KeyGeneration.generateSystemParameters()

    // first authority
    // generate the public and private key share and the key generation proof
    const share1: ECelGamal.KeyShare = ECelGamal.KeyGeneration.generateKeyShares()
    const uniqueId1 = 'IamReallyUnique;-)'
    const proof1: KeyShareProof = ECelGamal.KeyGeneration.generateKeyGenerationProof(params, share1, uniqueId1)
    const verified1: boolean = ECelGamal.KeyGeneration.verifyKeyGenerationProof(params, proof1, share1.h_, uniqueId1)
    expect(verified1).to.be.true

    // second authority
    // generate the public and private key share and the key generation proof
    const share2: ECelGamal.KeyShare = ECelGamal.KeyGeneration.generateKeyShares()
    const uniqueId2 = 'IamMuchMoreUnique_o.o'
    const proof2: KeyShareProof = ECelGamal.KeyGeneration.generateKeyGenerationProof(params, share2, uniqueId2)
    const verified2: boolean = ECelGamal.KeyGeneration.verifyKeyGenerationProof(params, proof2, share2.h_, uniqueId2)
    expect(verified2).to.be.true

    prnt && console.log('1: pk, sk', share1.h_, share1.sk_)
    prnt && console.log('2: pk, sk', share2.h_, share2.sk_)

    // combined keys
    const publicKey = ECelGamal.KeyGeneration.combinePublicKeys([share1.h_, share2.h_])
    const privateKey = ECelGamal.KeyGeneration.combinePrivateKeys(params, [share1.sk_, share2.sk_])

    prnt && console.log('pk', publicKey)
    prnt && console.log('sk', privateKey)

    // encrypt a single yes vote -> we use the generator
    const plaintext = activeCurve.curve.g
    const cipherText = ECelGamal.Encryption.encrypt(plaintext, publicKey)

    prnt && console.log('plaintext', plaintext)
    prnt && console.log('cipherText (a,b)', cipherText.a, cipherText.b)

    // decrypt shares
    const share1Decrypted = ECelGamal.KeyGeneration.decryptShare(cipherText, share1.sk_)
    const share2Decrypted = ECelGamal.KeyGeneration.decryptShare(cipherText, share2.sk_)

    prnt && console.log('share 1 - decrypted\t', share1Decrypted)
    prnt && console.log('share 2 - decrypted\t', share2Decrypted)

    // finish decryption by combining decrypted shares
    const distributedDecrypted = ECelGamal.KeyGeneration.combineDecryptedShares(cipherText, [share1Decrypted, share2Decrypted])
    const result1 = ECelGamal.Voting.checkDecrypedSum(distributedDecrypted)

    // decrypt with combined private key
    const combinedDecryption = ECelGamal.Encryption.decrypt(cipherText, privateKey)
    const result2 = ECelGamal.Voting.checkDecrypedSum(combinedDecryption)

    prnt && console.log('distributed decryption\t', distributedDecrypted.toString())
    prnt && console.log('combined decryption\t', combinedDecryption.toString())

    // check that decrypting both ways results in the same result
    expect(distributedDecrypted).to.eql(combinedDecryption)
    expect(result1).to.equal(result2)
  })
})
