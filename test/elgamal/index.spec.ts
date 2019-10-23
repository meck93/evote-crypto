export {}
import {
  generateKeys,
  encrypt,
  decrypt1,
  decrypt2,
  add,
} from '../../src/elgamal'

const BN = require('bn.js')
const random = require('random')
const { expect } = require('chai')

describe('ElGamal Index', () => {
  it('compare decryption implementations', () => {
    const prnt = false
    const [pk, sk] = generateKeys(7, 3)

    const message = new BN(random.int(1, pk.p - 1), 10)
    for (let i = 0; i < 10; i++) {
      prnt && console.log(i)
      prnt && console.log('prime      (p)\t', pk.p)
      prnt && console.log('generator  (g)\t', pk.g)
      prnt && console.log('dec secret (x)\t', sk)
      prnt && console.log('           (h)\t', pk.h)
      prnt && console.log('plaintext    (m)', message)
      prnt && console.log('------------------------')

      const m_enc = encrypt(message, pk, prnt)
      const m_d1 = decrypt1(m_enc, sk, pk, prnt)
      const m_d2 = decrypt2(m_enc, sk, pk, prnt)

      expect(m_d1.eq(message)).to.be.true
      expect(m_d2.eq(message)).to.be.true
      expect(m_d1.eq(m_d2)).to.be.true
    }
  })

  it('homomorphic addition', () => {
    const _p = 137
    const _g = 51

    // generate random masseges of max size (p - 1)/2
    // so that the sum is max p-1
    const _m1 = random.int(1, (_p - 1) / 2)
    const _m2 = random.int(1, (_p - 1) / 2)

    for (let i = 0; i < 10; i++) {
      const [pk, sk] = generateKeys(_p, _g)

      const m1 = new BN(_m1, 10)
      const e_m1 = encrypt(m1, pk)

      const m2 = new BN(_m2, 10)
      const e_m2 = encrypt(m2, pk)

      const d_sum = decrypt1(add(e_m1, e_m2, pk), sk, pk)

      expect(d_sum.toNumber()).to.equal(_m1 + _m2)
    }
  })
})
