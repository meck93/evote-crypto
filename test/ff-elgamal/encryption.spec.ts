export { }
import BN = require("bn.js")
import { FFelGamal } from '../../src/index'

const random = require('random')
const { expect } = require('chai')

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
      expect(FFelGamal.Encryption.encodeMessage(value.decoded, pk).toNumber()).to.equal(value.encoded)
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
      expect(FFelGamal.Encryption.decodeMessage(value.encoded, pk).toNumber()).to.equal(value.decoded)
    }
  })

  it('compare decryption implementations', () => {
    const prnt = false
    const [pk, sk] = FFelGamal.Encryption.generateKeys(11, 3)

    const message = random.int(1, pk.q.sub((new BN(1))))
    for (let i = 0; i < 10; i++) {
      prnt && console.log(i)
      prnt && console.log('prime      (p)\t', pk.p)
      prnt && console.log('generator  (g)\t', pk.g)
      prnt && console.log('dec secret (x)\t', sk)
      prnt && console.log('           (h)\t', pk.h)
      prnt && console.log('plaintext    (m)', message)
      prnt && console.log('------------------------')

      const m_enc = FFelGamal.Encryption.encrypt(message, pk, prnt)
      const m_d1 = FFelGamal.Encryption.decrypt1(m_enc, sk, pk, prnt)
      const m_d2 = FFelGamal.Encryption.decrypt2(m_enc, sk, pk, prnt)

      expect(m_d1.toNumber()).to.equal(message)
      expect(m_d2.toNumber()).to.equal(message)
      expect(m_d1.eq(m_d2)).to.be.true
    }
  })

  it('homomorphic addition', () => {
    const _p = 137
    const _g = 51

    for (let i = 0; i < 10; i++) {
      const [pk, sk] = FFelGamal.Encryption.generateKeys(_p, _g)

      // generate random messages of max size (p - 1)/2
      // so that the sum is max p-1
      const m1 = random.int(1, (_p - 1) / 2)
      const m2 = random.int(1, (_p - 1) / 2)

      const e_m1 = FFelGamal.Encryption.encrypt(m1, pk)
      const e_m2 = FFelGamal.Encryption.encrypt(m2, pk)

      const d_sum = FFelGamal.Encryption.decrypt1(FFelGamal.Encryption.add(e_m1, e_m2, pk), sk, pk)

      expect(d_sum.toNumber()).to.equal(m1 + m2)
    }
  })
})
