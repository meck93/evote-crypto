export {}
import { ECelGamal } from '../../src/index'
import { SumProof } from '../../src/models'
import { ECParams, ECCipher } from '../../src/ec-elgamal/models'
import { ec, curve } from 'elliptic'

import BN = require('bn.js')

import { expect, assert } from 'chai'

const EC = require('elliptic').ec
const secp256k1 = new EC('secp256k1')

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = secp256k1.curve.g
const noVoteOnCurve = secp256k1.curve.g.neg()

describe('Elliptic Curve ElGamal Sum ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(secp256k1.curve.validate(noVoteOnCurve) && secp256k1.curve.validate(yesVoteOnCurve))
  })

  it('Should generate a valid sum proof for a number of votes', () => {
    const keyPair: ec.KeyPair = secp256k1.genKeyPair()
    const privateKey: BN = keyPair.getPrivate()
    const publicKey: curve.base.BasePoint = keyPair.getPublic()

    const params: ECParams = { p: secp256k1.curve.p, h: publicKey, g: secp256k1.curve.g, n: secp256k1.curve.n }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    const generateAndVerifySum = (_votes: number[], _result: number) => {
      const votes: ECCipher[] = []

      for (const vote of _votes) {
        vote === 1 && votes.push(ECelGamal.Encryption.encrypt(yesVoteOnCurve, publicKey))
        vote === 0 && votes.push(ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey))
      }

      // homomorphically add votes + generate sum proof
      const encryptedSum: ECCipher = ECelGamal.Voting.addVotes(votes, publicKey)
      const sumProof: SumProof = ECelGamal.SumZKP.generateSumProof(encryptedSum, params, privateKey, uniqueID)

      // verify proof
      const verifiedSumProof: boolean = ECelGamal.SumZKP.verifySumProof(encryptedSum, sumProof, params, publicKey, uniqueID)
      expect(verifiedSumProof).to.be.true

      // decrypt sum
      const decryptedSum: curve.base.BasePoint = ECelGamal.Encryption.decrypt(encryptedSum, privateKey)
      const result = ECelGamal.Voting.checkDecrypedSum(decryptedSum)

      const summary = ECelGamal.Voting.getSummary(votes.length, result)
      console.log(_result, _votes, result, 'Total:', summary.total, '| Yes:', summary.yes, '| No:', summary.no)

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
