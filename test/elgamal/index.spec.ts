export {}
import { Cipher, ElGamal, ElGamalVoting } from '../../src/index'

const random = require('random')
const { expect } = require('chai')

describe('ElGamal Index', () => {
  it('compare decryption implementations', () => {
    const prnt = false
    const [pk, sk] = ElGamal.generateKeys(11, 3)

    const message = random.int(1, pk.q - 1)
    for (let i = 0; i < 10; i++) {
      prnt && console.log(i)
      prnt && console.log('prime      (p)\t', pk.p)
      prnt && console.log('generator  (g)\t', pk.g)
      prnt && console.log('dec secret (x)\t', sk)
      prnt && console.log('           (h)\t', pk.h)
      prnt && console.log('plaintext    (m)', message)
      prnt && console.log('------------------------')

      const m_enc = ElGamal.encrypt(message, pk, prnt)
      const m_d1 = ElGamal.decrypt1(m_enc, sk, pk, prnt)
      const m_d2 = ElGamal.decrypt2(m_enc, sk, pk, prnt)

      expect(m_d1.toNumber()).to.equal(message)
      expect(m_d2.toNumber()).to.equal(message)
      expect(m_d1.eq(m_d2)).to.be.true
    }
  })

  it('homomorphic addition', () => {
    const _p = 137
    const _g = 51

    for (let i = 0; i < 10; i++) {
      const [pk, sk] = ElGamal.generateKeys(_p, _g)

      // generate random messages of max size (p - 1)/2
      // so that the sum is max p-1
      const m1 = random.int(1, (_p - 1) / 2)
      const m2 = random.int(1, (_p - 1) / 2)

      const e_m1 = ElGamal.encrypt(m1, pk)
      const e_m2 = ElGamal.encrypt(m2, pk)

      const d_sum = ElGamal.decrypt1(ElGamal.add(e_m1, e_m2, pk), sk, pk)

      expect(d_sum.toNumber()).to.equal(m1 + m2)
    }
  })

  it('vote', () => {
    const vote = (_result: number, _votes: number[]) => {
      const [pk, sk] = ElGamal.generateKeys(137, 51)

      const votes: Cipher[] = []
      for (const vote of _votes) {
        vote === 1 && votes.push(ElGamalVoting.generateYesVote(pk))
        vote === 0 && votes.push(ElGamalVoting.generateNoVote(pk))
      }

      const result = ElGamalVoting.tallyVotes(pk, sk, votes)
      const summary = ElGamalVoting.getSummary(votes.length, result)
      console.log(_result, _votes, result, 'Total:', summary.total, '| Yes:', summary.yes, '| No:', summary.no)

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter(v => v === 1).length)
      expect(summary.no).to.equal(_votes.filter(v => v === 0).length)
    }

    // voters:  0
    // results: 2^0 = 1
    vote(0, [])

    // voters:  1
    // results: 2^1 = 2
    vote(0, [0])
    vote(1, [1])

    // voters:  2
    // results: 2^2 = 4
    vote(0, [0, 0])
    vote(1, [0, 1])
    vote(1, [1, 0])
    vote(2, [1, 1])

    // voters:  3
    // results: 2^3 = 8
    vote(0, [0, 0, 0])
    vote(1, [0, 0, 1])
    vote(1, [0, 1, 0])
    vote(2, [0, 1, 1])
    vote(1, [1, 0, 0])
    vote(2, [1, 0, 1])
    vote(2, [1, 1, 0])
    vote(3, [1, 1, 1])

    // voters:  4
    // results: 2^4 = 16
    vote(0, [0, 0, 0, 0])
    vote(1, [0, 0, 0, 1])
    vote(1, [0, 0, 1, 0])
    vote(2, [0, 0, 1, 1])
    vote(1, [0, 1, 0, 0])
    vote(2, [0, 1, 0, 1])
    vote(2, [0, 1, 1, 0])
    vote(3, [0, 1, 1, 1])
    vote(1, [1, 0, 0, 0])
    vote(2, [1, 0, 0, 1])
    vote(2, [1, 0, 1, 0])
    vote(3, [1, 0, 1, 1])
    vote(2, [1, 1, 0, 0])
    vote(3, [1, 1, 0, 1])
    vote(3, [1, 1, 1, 0])
    vote(4, [1, 1, 1, 1])
  })

  it('test', () => {
    // generated test values with http://www.bluetulip.org/2014/programs/primitive.html
    expect(ElGamal.getGs(3)).to.eql([2])
    expect(ElGamal.getGs(5)).to.eql([2, 3])
    expect(ElGamal.getGs(7)).to.eql([3, 5])
    expect(ElGamal.getGs(11)).to.eql([2, 6, 7, 8])
    expect(ElGamal.getGs(13)).to.eql([2, 6, 7, 11])
    expect(ElGamal.getGs(17)).to.eql([3, 5, 6, 7, 10, 11, 12, 14])
    expect(ElGamal.getGs(19)).to.eql([2, 3, 10, 13, 14, 15])
    expect(ElGamal.getGs(23)).to.eql([5, 7, 10, 11, 14, 15, 17, 19, 20, 21])
    expect(ElGamal.getGs(29)).to.eql([2, 3, 8, 10, 11, 14, 15, 18, 19, 21, 26, 27])
    expect(ElGamal.getGs(31)).to.eql([3, 11, 12, 13, 17, 21, 22, 24])
    expect(ElGamal.getGs(37)).to.eql([2, 5, 13, 15, 17, 18, 19, 20, 22, 24, 32, 35])
    expect(ElGamal.getGs(41)).to.eql([6, 7, 11, 12, 13, 15, 17, 19, 22, 24, 26, 28, 29, 30, 34, 35])
    expect(ElGamal.getGs(43)).to.eql([3, 5, 12, 18, 19, 20, 26, 28, 29, 30, 33, 34])
    expect(ElGamal.getGs(47)).to.eql([
      5,
      10,
      11,
      13,
      15,
      19,
      20,
      22,
      23,
      26,
      29,
      30,
      31,
      33,
      35,
      38,
      39,
      40,
      41,
      43,
      44,
      45,
    ])
  })
})
