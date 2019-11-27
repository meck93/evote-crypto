import { assert, expect } from 'chai'
import { ECelGamal } from '../../../src/index'

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = ECelGamal.Curve.g
const noVoteOnCurve = ECelGamal.Curve.g.neg()

describe('Elliptic Curve ElGamal Sum ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(ECelGamal.Curve.validate(noVoteOnCurve) && ECelGamal.Curve.validate(yesVoteOnCurve))
  })

  it('Should generate a valid sum proof for a number of votes', () => {
    const log = false
    const { h: publicKey, sk: privateKey } = ECelGamal.SystemSetup.generateKeyPair()

    const params: ECelGamal.SystemParameters = {
      p: ECelGamal.Curve.p,
      g: ECelGamal.Curve.g,
      n: ECelGamal.Curve.n,
    }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    const generateAndVerifySum = (_votes: number[], _result: number): void => {
      const votes: ECelGamal.Cipher[] = []

      for (const vote of _votes) {
        vote === 1 && votes.push(ECelGamal.Encryption.encrypt(yesVoteOnCurve, publicKey))
        vote === 0 && votes.push(ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey))
      }

      // homomorphically add votes + generate sum proof
      const encryptedSum: ECelGamal.Cipher = ECelGamal.Voting.addVotes(votes, publicKey)
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
      const decryptedSum: ECelGamal.CurvePoint = ECelGamal.Encryption.decrypt(encryptedSum, privateKey)
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
