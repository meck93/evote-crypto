export {}
import { Cipher, ElGamal, ElGamalVoting } from '../../src/index'
import { createZKP, verifyZKP } from '../../src/zkp/elgamalZKP'

const random = require('random')
const { expect } = require('chai')

describe.only('ElGamal ZKP Proof', () => {
  it.only('create and verify proof', () => {
    const prnt = true
    const [pk, sk] = ElGamal.generateKeys(7, 3)

    const message = random.int(1, pk.p - 1)
    for (let i = 3; i < 4; i++) {
      prnt && console.log(i)
      prnt && console.log('prime      (p)\t', pk.p)
      prnt && console.log('generator  (g)\t', pk.g)
      prnt && console.log('dec secret (x)\t', sk)
      prnt && console.log('           (h)\t', pk.h)
      prnt && console.log('plaintext    (m)', message)
      prnt && console.log('------------------------')

      const m_enc = ElGamal.encrypt(message, pk, false)
      // prnt && console.log(m_enc)
      const proof = createZKP(m_enc, pk)
      // prnt && console.log(proof)

      const verifiedProof = verifyZKP(proof, pk)
      // prnt && console.log(verifiedProof)

      const m_d1 = ElGamal.decrypt1(m_enc, sk, pk, false)
      const m_d2 = ElGamal.decrypt2(m_enc, sk, pk, false)

      expect(m_d1.toNumber()).to.equal(message)
      expect(m_d2.toNumber()).to.equal(message)
      expect(m_d1.eq(m_d2)).to.be.true
    }
  })
})
