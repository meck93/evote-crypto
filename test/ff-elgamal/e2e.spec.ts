export {}
import BN = require('bn.js')
import { expect } from 'chai'
import { FFelGamal } from '../../src/index'

const random = require('random')
const web3 = require('web3')

describe('ElGamal Finite Field E2E Test', () => {
  it('complete vote', () => {
    const vote = (p: number, g: number, _result: number, _votes: number[]): void => {
      const govID = 'GOV_ID_SUPER_SECURE_:-)'

      const prnt = true

      let sp: FFelGamal.SystemParameters
      let pk: BN
      let sk: BN

      try {
        ;[sp, { h: pk, sk }] = FFelGamal.SystemSetup.generateSystemParametersAndKeys(p, g)
        prnt && console.log('p:', sp.p, 'q:', sp.q, 'g:', sp.g, 'pk:', pk, 'sk:', sk)
      } catch (error) {
        console.error(error)
      }

      const votes: FFelGamal.Cipher[] = []

      // generate votes and proofs with random IDs
      for (const vote of _votes) {
        const id = web3.utils.soliditySha3(random.int(1, Math.pow(2, 16)))

        if (vote === 1) {
          const encYesVote = FFelGamal.Voting.generateYesVote(sp, pk)
          votes.push(encYesVote)

          const encYesProof = FFelGamal.MembershipProof.generateYesProof(encYesVote, sp, pk, id)

          const validVote = FFelGamal.MembershipProof.verify(encYesVote, encYesProof, sp, pk, id)
          expect(validVote).to.be.true
        } else {
          const encNoVote = FFelGamal.Voting.generateNoVote(sp, pk)
          votes.push(encNoVote)

          const encNoProof = FFelGamal.MembershipProof.generateNoProof(encNoVote, sp, pk, id)

          const validVote = FFelGamal.MembershipProof.verify(encNoVote, encNoProof, sp, pk, id)
          expect(validVote).to.be.true
        }
      }

      // homomorphically add all votes and create sum proof
      const encryptedSum = FFelGamal.Voting.addVotes(votes, sp)
      const sumProof = FFelGamal.DecryptionProof.generate(encryptedSum, sp, sk, govID)

      // verifiy the sum proof
      const validSum = FFelGamal.DecryptionProof.verify(encryptedSum, sumProof, sp, pk, govID)
      expect(validSum).to.be.true

      // decrypt the sum
      const decryptedSum = FFelGamal.Encryption.decrypt1(encryptedSum, sk, sp)
      const summary = FFelGamal.Voting.getSummary(votes.length, decryptedSum.toNumber())
      prnt &&
        console.log(
          _result,
          _votes,
          'Total:',
          summary.total,
          '| Yes:',
          summary.yes,
          '| No:',
          summary.no
        )

      expect(decryptedSum.toNumber()).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter(v => v === 1).length)
      expect(summary.no).to.equal(_votes.filter(v => v === 0).length)
    }

    // voters: 3
    // result: 2 yes, 1 no
    // p = 23, q = 11, g = 2
    vote(23, 2, 2, [1, 1, 0])

    // voters: 26
    // result: 17 yes, 9 no
    // p = 107, q = 53, g = 3
    vote(107, 3, 17, [1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1])
  })
})
