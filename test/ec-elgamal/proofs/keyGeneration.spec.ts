export {}
import { ECelGamal } from '../../../src/index'
import { ECpow, ECmul } from '../../../src/ec-elgamal/helper'

import { expect } from 'chai'
import { activeCurve } from '../../../src/ec-elgamal/activeCurve'
import { CurvePoint, KeyShareProof } from '../../../src/ec-elgamal/models'

const generateKeyPairs = (n: number): ECelGamal.KeyPair[] => {
  const res: ECelGamal.KeyPair[] = []
  for (let i = 0; i < n; i++) {
    res.push(ECelGamal.SystemSetup.generateKeyPair())
  }
  return res
}

describe('Elliptic Curve ElGamal Distributed Key Generation', () => {
  it('generate and verify (distributed) key share', () => {
    for (let i = 0; i < 10; i++) {
      const log = false

      // generate the system parameters: P, Q, G
      const params: ECelGamal.SystemParameters = ECelGamal.SystemSetup.generateSystemParameters()
      const { g } = params

      // generate the public and private key share: H_, SK_
      const share: ECelGamal.KeyPair = ECelGamal.SystemSetup.generateKeyPair()
      const { h: h1, sk: sk1 } = share

      expect(h1).to.eql(ECpow(g, sk1))

      log && console.log('Key Parts')
      log && console.log('h_:\t', h1.toString())
      log && console.log('sk_:\t', sk1.toString())
      log && console.log()

      // generate the key share generation proof
      const uniqueId = 'IamReallyUnique;-)'
      const proof: KeyShareProof = ECelGamal.Proof.KeyGeneration.generate(
        params,
        share,
        uniqueId
      )
      const { c: c1, d: d1 } = proof

      log && console.log('Proof Parts')
      log && console.log('c:\t', c1.toString())
      log && console.log('d1:\t', d1.toString())
      log && console.log()

      // verify that the key share has been generated truthfully
      const verifiedProof: boolean = ECelGamal.Proof.KeyGeneration.verify(
        params,
        proof,
        h1,
        uniqueId
      )

      expect(verifiedProof).to.be.true
    }
  })

  it('combine public keys', () => {
    // generate one share
    let keyPairs: ECelGamal.KeyPair[] = generateKeyPairs(1)
    let shares: CurvePoint[] = [keyPairs[0].h]
    let product: CurvePoint = shares[0]
    expect(ECelGamal.SystemSetup.combinePublicKeys(shares)).to.eql(product)

    // generate two shares + combine them
    keyPairs = generateKeyPairs(2)
    shares = [keyPairs[0].h, keyPairs[1].h]
    product = ECmul(shares[0], shares[1])
    expect(ECelGamal.SystemSetup.combinePublicKeys(shares)).to.eql(product)

    // generate three shares + combine them
    keyPairs = generateKeyPairs(3)
    shares = [keyPairs[0].h, keyPairs[1].h, keyPairs[2].h]
    product = ECmul(ECmul(shares[0], shares[1]), shares[2])
    expect(ECelGamal.SystemSetup.combinePublicKeys(shares)).to.eql(product)
  })

  it('perform distributed key generation', () => {
    const log = false

    const params: ECelGamal.SystemParameters = ECelGamal.SystemSetup.generateSystemParameters()

    // first authority
    // generate the public and private key share and the key generation proof
    const share1: ECelGamal.KeyPair = ECelGamal.SystemSetup.generateKeyPair()
    const uniqueId1 = 'IamReallyUnique;-)'
    const proof1: KeyShareProof = ECelGamal.Proof.KeyGeneration.generate(
      params,
      share1,
      uniqueId1
    )
    const verified1: boolean = ECelGamal.Proof.KeyGeneration.verify(
      params,
      proof1,
      share1.h,
      uniqueId1
    )
    expect(verified1).to.be.true

    // second authority
    // generate the public and private key share and the key generation proof
    const share2: ECelGamal.KeyPair = ECelGamal.SystemSetup.generateKeyPair()
    const uniqueId2 = 'IamMuchMoreUnique_o.o'
    const proof2: KeyShareProof = ECelGamal.Proof.KeyGeneration.generate(
      params,
      share2,
      uniqueId2
    )
    const verified2: boolean = ECelGamal.Proof.KeyGeneration.verify(
      params,
      proof2,
      share2.h,
      uniqueId2
    )
    expect(verified2).to.be.true

    log && console.log('1: pk, sk', share1.h, share1.sk)
    log && console.log('2: pk, sk', share2.h, share2.sk)

    // combined keys
    const publicKey = ECelGamal.SystemSetup.combinePublicKeys([share1.h, share2.h])
    const privateKey = ECelGamal.SystemSetup.combinePrivateKeys(params, [share1.sk, share2.sk])

    log && console.log('pk', publicKey)
    log && console.log('sk', privateKey)

    // encrypt a single yes vote -> we use the generator
    const plaintext = activeCurve.curve.g
    const cipherText = ECelGamal.Encryption.encrypt(plaintext, publicKey)

    log && console.log('plaintext', plaintext)
    log && console.log('cipherText (a,b)', cipherText.a, cipherText.b)

    // decrypt shares
    const share1Decrypted = ECelGamal.Encryption.decryptShare(cipherText, share1.sk)
    const share2Decrypted = ECelGamal.Encryption.decryptShare(cipherText, share2.sk)

    log && console.log('share 1 - decrypted\t', share1Decrypted)
    log && console.log('share 2 - decrypted\t', share2Decrypted)

    // finish decryption by combining decrypted shares
    const distributedDecrypted = ECelGamal.Encryption.combineDecryptedShares(cipherText, [
      share1Decrypted,
      share2Decrypted,
    ])
    const result1 = ECelGamal.Voting.checkDecrypedSum(distributedDecrypted)

    // decrypt with combined private key
    const combinedDecryption = ECelGamal.Encryption.decrypt(cipherText, privateKey)
    const result2 = ECelGamal.Voting.checkDecrypedSum(combinedDecryption)

    log && console.log('distributed decryption\t', distributedDecrypted.toString())
    log && console.log('combined decryption\t', combinedDecryption.toString())

    // check that decrypting both ways results in the same result
    expect(distributedDecrypted).to.eql(combinedDecryption)
    expect(result1).to.equal(result2)
  })
})
