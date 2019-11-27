export {}
import { ECelGamal } from '../../../src/index'
import { CurvePoint, Cipher } from '../../../src/ec-elgamal/models'
import { ec } from 'elliptic'

import BN = require('bn.js')

import { expect, assert } from 'chai'
import { activeCurve } from '../../../src/ec-elgamal/activeCurve'

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = activeCurve.curve.g
const noVoteOnCurve = activeCurve.curve.g.neg()

describe('Elliptic Curve ElGamal Sum ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(activeCurve.curve.validate(noVoteOnCurve) && activeCurve.curve.validate(yesVoteOnCurve))
  })

  it('Should generate a valid sum proof for a number of votes', () => {
    const log = false
    const keyPair: ec.KeyPair = activeCurve.genKeyPair()
    const privateKey: BN = keyPair.getPrivate()
    const publicKey: CurvePoint = keyPair.getPublic() as CurvePoint

    const params: ECelGamal.SystemParameters = {
      p: activeCurve.curve.p,
      g: activeCurve.curve.g,
      n: activeCurve.curve.n,
    }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    const generateAndVerifySum = (_votes: number[], _result: number): void => {
      const votes: Cipher[] = []

      for (const vote of _votes) {
        vote === 1 && votes.push(ECelGamal.Encryption.encrypt(yesVoteOnCurve, publicKey))
        vote === 0 && votes.push(ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey))
      }

      // homomorphically add votes + generate sum proof
      const encryptedSum: Cipher = ECelGamal.Voting.addVotes(votes, publicKey)
      const sumProof: ECelGamal.Proof.DecryptionProof = ECelGamal.Proof.Decryption.generate(
        encryptedSum,
        params,
        privateKey,
        uniqueID
      )

      // verify proof
      const verifiedSumProof: boolean = ECelGamal.Proof.Decryption.verify(
        encryptedSum,
        sumProof,
        params,
        publicKey,
        uniqueID
      )
      expect(verifiedSumProof).to.be.true

      // decrypt sum
      const decryptedSum: CurvePoint = ECelGamal.Encryption.decrypt(encryptedSum, privateKey)
      const result = ECelGamal.Voting.checkDecrypedSum(decryptedSum)

      const summary = ECelGamal.Voting.getSummary(votes.length, result)
      log &&
        console.log(
          _result,
          _votes,
          result,
          'Total:',
          summary.total,
          '| Yes:',
          summary.yes,
          '| No:',
          summary.no
        )

      expect(result).to.equal(_result)
      expect(summary.yes).to.equal(_votes.filter(v => v === 1).length)
      expect(summary.no).to.equal(_votes.filter(v => v === 0).length)
    }

    // Yes: 3, No: 2 -> Result: 1
    generateAndVerifySum([1, 1, 1, 0, 0], 1)

    // Yes: 8, No: 10 -> Result: -2
    generateAndVerifySum([0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0], -2)
  })
})
