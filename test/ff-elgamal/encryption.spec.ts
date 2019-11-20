export {}
import BN = require('bn.js')
import { FFelGamal } from '../../src/index'
import { getSecureRandomValue } from '../../src/ff-elgamal/helper'
import { expect } from 'chai'

describe('Finite Field ElGamal Encryption', () => {
  it('should encode a message', () => {
    const [pk] = FFelGamal.Encryption.generateKeys(11, 3)

    const values = [
      { decoded: 0, encoded: 1 },
      { decoded: 1, encoded: 3 },
      { decoded: 2, encoded: 9 },
      { decoded: 3, encoded: 5 },
      { decoded: 4, encoded: 4 },
      { decoded: 5, encoded: 1 },
      { decoded: 6, encoded: 3 },
      { decoded: 7, encoded: 9 },
      { decoded: 8, encoded: 5 },
      { decoded: 9, encoded: 4 },
      { decoded: 10, encoded: 1 },
      { decoded: 11, encoded: 3 },
    ]

    for (const value of values) {
      expect(FFelGamal.Encryption.encodeMessage(value.decoded, pk).toNumber()).to.equal(
        value.encoded
      )
    }
  })

  it('should decode an encoded message', () => {
    const [pk] = FFelGamal.Encryption.generateKeys(11, 3)

    const values = [
      { decoded: 0, encoded: 1 },
      { decoded: 1, encoded: 3 },
      { decoded: 2, encoded: 9 },
      { decoded: 3, encoded: 5 },
      { decoded: 4, encoded: 4 },
      // TODO: define constraints for message space
      /*{ decoded: 5, encoded: 1 },
      { decoded: 6, encoded: 3 },
      { decoded: 7, encoded: 9 },
      { decoded: 8, encoded: 5 },
      { decoded: 9, encoded: 4 },
      { decoded: 10, encoded: 1 },
      { decoded: 11, encoded: 3 },*/
    ]

    for (const value of values) {
      expect(FFelGamal.Encryption.decodeMessage(value.encoded, pk).toNumber()).to.equal(
        value.decoded
      )
    }
  })

  it('compare decryption implementations', () => {
    const prnt = false
    const [pk, sk] = FFelGamal.Encryption.generateKeys(11, 3)

    const message = getSecureRandomValue(pk.q)
    for (let i = 0; i < 10; i++) {
      prnt && console.log(i)
      prnt && console.log('prime      (p)\t', pk.p)
      prnt && console.log('generator  (g)\t', pk.g)
      prnt && console.log('dec secret (x)\t', sk)
      prnt && console.log('           (h)\t', pk.h)
      prnt && console.log('plaintext    (m)', message)
      prnt && console.log('------------------------')

      const mEnc = FFelGamal.Encryption.encrypt(message, pk, prnt)
      const mD1 = FFelGamal.Encryption.decrypt1(mEnc, sk, pk, prnt)
      const mD2 = FFelGamal.Encryption.decrypt2(mEnc, sk, pk, prnt)

      expect(mD1.eq(message)).to.be.true
      expect(mD2.eq(message)).to.be.true
      expect(mD1.eq(mD2)).to.be.true
    }
  })

  it('homomorphic addition', () => {
    const _p = 137
    const _g = 51

    for (let i = 0; i < 10; i++) {
      const [pk, sk] = FFelGamal.Encryption.generateKeys(_p, _g)

      // generate random messages of max size (p - 1)/2
      // so that the sum is max p-1
      const m1 = getSecureRandomValue(new BN((_p - 1) / 2))
      const m2 = getSecureRandomValue(new BN((_p - 1) / 2))

      const eM1 = FFelGamal.Encryption.encrypt(m1, pk)
      const eM2 = FFelGamal.Encryption.encrypt(m2, pk)

      const dSum = FFelGamal.Encryption.decrypt1(FFelGamal.Encryption.add(eM1, eM2, pk), sk, pk)

      expect(dSum.eq(m1.add(m2))).to.be.true
    }
  })
})
