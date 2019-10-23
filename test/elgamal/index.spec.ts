export {}
import {
  generateKeys,
  encrypt,
  decrypt1,
  decrypt2,
  add,
} from '../../src/elgamal'
import { Cipher } from '../../src/elgamal/models'
import {
  generateNoVote,
  generateYesVote,
  tallyVotes,
} from '../../src/elgamal/voting'

const BN = require('bn.js')
const random = require('random')
const { expect } = require('chai')

describe('ElGamal Index', () => {
  it('compare decryption implementations', () => {
    const prnt = false
    const [pk, sk] = generateKeys(7, 3)

    const message = random.int(1, pk.p - 1)
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

      expect(m_d1.toNumber()).to.equal(message)
      expect(m_d2.toNumber()).to.equal(message)
      expect(m_d1.eq(m_d2)).to.be.true
    }
  })

  it('homomorphic addition', () => {
    const _p = 137
    const _g = 51

    for (let i = 0; i < 10; i++) {
      const [pk, sk] = generateKeys(_p, _g)

      // generate random messages of max size (p - 1)/2
      // so that the sum is max p-1
      const m1 = random.int(1, (_p - 1) / 2)
      const m2 = random.int(1, (_p - 1) / 2)

      const e_m1 = encrypt(m1, pk)
      const e_m2 = encrypt(m2, pk)

      const d_sum = decrypt1(add(e_m1, e_m2, pk), sk, pk)

      expect(d_sum.toNumber()).to.equal(m1 + m2)
    }
  })

  it('vote', () => {
    const [pk, sk] = generateKeys(137, 51)
    const log = true

    const yesVotes = 55
    const noVotes = 14
    let votes: Cipher[] = []

    for (let i = 0; i < yesVotes; i++) {
      votes.push(generateYesVote(pk))
      log && console.log(votes[votes.length - 1])
    }

    for (let i = 0; i < noVotes; i++) {
      votes.push(generateNoVote(pk))
      log && console.log(votes[votes.length - 1])
    }

    const result = tallyVotes(pk, sk, votes)

    expect(result).to.equal(yesVotes)
  })
})
