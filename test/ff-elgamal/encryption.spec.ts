export {}
import { FFelGamal } from '../../src/index'

const random = require('random')
const { expect } = require('chai')

describe('Finite Field ElGamal Encryption', () => {
  it('compare decryption implementations', () => {
    const prnt = false
    const [pk, sk] = FFelGamal.Encryption.generateKeys(11, 3)

    const message = random.int(1, pk.q - 1)
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
