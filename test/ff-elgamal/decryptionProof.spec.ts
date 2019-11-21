export {}
import { FFelGamal } from '../../src/index'
import { getSecureRandomValue } from '../../src/ff-elgamal/helper'
import { expect } from 'chai'

describe('ElGamal Finite Field NIZKP for Decryption', () => {
  it('create and verify sum proof', () => {
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // generate and verify 10 proofs (with different random variables and different random messages)
    const test = (p: number, g: number): void => {
      for (let i = 0; i < 10; i++) {
        const prnt = false
        let sp, pk, sk
        try {
          ;[sp, { h: pk, sk }] = FFelGamal.Encryption.generateSystemParametersAndKeys(p, g)
          prnt && console.log('p:', sp.p, 'q:', sp.q, 'g:', sp.g)
        } catch (error) {
          console.error(error)
          break
        }

        // sum
        const sum = getSecureRandomValue(sp.q)
        prnt && console.log(`Sum Proof for Message: ${sum}`)

        const sumEnc = FFelGamal.Encryption.encrypt(sum, sp, pk, prnt)
        const proof = FFelGamal.DecryptionProof.generate(sumEnc, sp, sk, uniqueID)

        const verifiedSumProof = FFelGamal.DecryptionProof.verify(sumEnc, proof, sp, pk, uniqueID)
        expect(verifiedSumProof).to.be.true

        const decSum = FFelGamal.Encryption.decrypt1(sumEnc, sk, sp, prnt)
        expect(decSum.eq(sum)).to.be.true
      }
    }

    // p = 23, q = 11 -> only generators that satisfy g^q mod p == 1
    test(23, 2)
    test(23, 6)
    test(23, 8)

    test(107, 3)
  })
})
