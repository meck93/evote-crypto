export { }
import { ECelGamal } from '../../src/index'
import { ValidVoteProof } from '../../src/models'
import { ec, curve } from 'elliptic'
import BN = require('bn.js')

import { expect, assert } from 'chai'
import { ECParams, ECCipher } from '../../src/ec-elgamal/models'

const EC = require('elliptic').ec
const curve25519 = new EC('curve25519-weier')

const prnt = true

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = curve25519.curve.g
const noVoteOnCurve = curve25519.curve.g.neg()

describe('Elliptic Curve ElGamal Vote ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function () {
    assert(curve25519.curve.validate(noVoteOnCurve) && curve25519.curve.validate(yesVoteOnCurve))
  })

  it('Should generate a valid proof for a vote (FIXME)', () => {
    const keyPair: ec.KeyPair = curve25519.genKeyPair()
    const privateKey: BN = keyPair.getPrivate()
    const publicKey: curve.base.BasePoint = keyPair.getPublic()

    const params: ECParams = { p: curve25519.curve.p, h: publicKey, g: curve25519.curve.g, n: curve25519.curve.n }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypted yes vote + generate proof
    prnt && console.log('yes proof\n')
    const encryptedYesVote: ECCipher = ECelGamal.Encryption.encrypt(yesVoteOnCurve, publicKey)
    const yesProof: ValidVoteProof = ECelGamal.VoteZKP.generateYesProof(encryptedYesVote, params, uniqueID)

    // verify yes vote proof
    const verifiedYesProof: boolean = ECelGamal.VoteZKP.verifyZKP(encryptedYesVote, yesProof, params, uniqueID)
    expect(verifiedYesProof).to.be.true

    // encrypt no vote + generate proof
    prnt && console.log('no proof\n')
    const encryptedNoVote: ECCipher = ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey)
    const noProof = ECelGamal.VoteZKP.generateNoProof(encryptedNoVote, params, uniqueID)

    // verify no vote proof
    const verifiedNoProof: boolean = ECelGamal.VoteZKP.verifyZKP(encryptedNoVote, noProof, params, uniqueID)
    expect(verifiedNoProof).to.be.true
  })
})
