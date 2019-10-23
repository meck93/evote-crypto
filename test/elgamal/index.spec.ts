export {}
import { generateKeys, encrypt, decrypt1, decrypt2 } from '../../src/elgamal'

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
})
