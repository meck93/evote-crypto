export {}
import { FFelGamal } from '../../src/index'

const random = require('random')
const { expect } = require('chai')

describe.only('ElGamal ZKP Sum Proof', () => {
  it('create and verify sum proof', () => {
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // generate and verify 10 proofs (with different random variables and different random messages)
    const test = (p: number, g: number) => {
      for (let i = 0; i < 10; i++) {
        const prnt = false
        prnt && console.log('p:', p, 'q:', (p - 1) / 2, 'g:', g)
        let pk
        let sk
        try {
          ;[pk, sk] = FFelGamal.Encryption.generateKeys(p, g)
        } catch (error) {
          console.error(error)
          break
        }

        // sum
        const sum = random.int(1, (p - 1) / 2 - 1)
        prnt && console.log(`Sum Proof for Message: ${sum}`)

        const sumEnc = FFelGamal.Encryption.encrypt(sum, pk, prnt)
        const proof = FFelGamal.SumZKP.generateSumProof(sumEnc, pk, sk, uniqueID)

        const verifiedSumProof = FFelGamal.SumZKP.verifySumProof(sumEnc, proof, pk, uniqueID)
        expect(verifiedSumProof).to.be.true

        const decSum = FFelGamal.Encryption.decrypt1(sumEnc, sk, pk, prnt)
        expect(decSum.toNumber()).to.equal(sum)
      }
    }

    // p = 23, q = 11 -> only generators that satisfy g^q mod p == 1
    test(23, 2)
    test(23, 6)
    test(23, 8)

    test(107, 3)
  })
})
