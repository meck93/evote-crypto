export {}
import { FFelGamal } from '../../src/index'
import { KeyShareProof } from '../../src/models'

const { expect } = require('chai')

describe.only('Finite Field ElGamal Distributed Key Generation', () => {
  it('perform distributed key generation', () => {
    for (let i = 0; i < 10; i++) {
      const prnt = true
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

      // TODO
      // 1. Generate another a second keySharesPair + Proof + Verify Proof
      // 2. Sum the private key shares: (sk1 + sk2) mod q => sk
      // 3. Multiply the public key shares: (h1 + h2) mod p => h
      // 4. Encrypt a message with the public key: h
      // 5. Decrypt the message with the private key: sk
      // 6. Verify that the two plaintexts are equal
    }
  })
})
