export { }
import { ECelGamal } from '../../src/index'
import { ValidVoteProof } from '../../src/models'
import { ec, curve } from 'elliptic'
import BN = require('bn.js')

import { expect, assert } from 'chai'
import { ECParams, ECCipher } from '../../src/ec-elgamal/models'

import { activeCurve } from '../../src/ec-elgamal/activeCurve'

const prnt = false

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = activeCurve.curve.g
const noVoteOnCurve = activeCurve.curve.g.neg()

describe('Elliptic Curve ElGamal Vote ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function () {
    assert(activeCurve.curve.validate(noVoteOnCurve) && activeCurve.curve.validate(yesVoteOnCurve))
  })

  it('Should generate an elliptic curve valid YES vote proof', () => {
    const keyPair: ec.KeyPair = activeCurve.genKeyPair()
    const publicKey: curve.base.BasePoint = keyPair.getPublic()

    const params: ECParams = { p: activeCurve.curve.p, h: publicKey, g: activeCurve.curve.g, n: activeCurve.curve.n }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypted yes vote + generate proof
    prnt && console.log('YES PROOF\n')
    const encryptedYesVote: ECCipher = ECelGamal.Encryption.encrypt(yesVoteOnCurve, publicKey)
    const yesProof: ValidVoteProof = ECelGamal.VoteZKP.generateYesProof(encryptedYesVote, params, uniqueID)

    // verify yes vote proof
    const verifiedYesProof: boolean = ECelGamal.VoteZKP.verifyZKP(encryptedYesVote, yesProof, params, uniqueID)
    expect(verifiedYesProof).to.be.true
  })

  it('Should generate an elliptic curve valid NO vote proof (FIXME)', () => {
    const keyPair: ec.KeyPair = activeCurve.genKeyPair()
    const publicKey: curve.base.BasePoint = keyPair.getPublic()

    const params: ECParams = { p: activeCurve.curve.p, h: publicKey, g: activeCurve.curve.g, n: activeCurve.curve.n }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypt no vote + generate proof
    prnt && console.log('NO PROOF\n')
    const encryptedNoVote: ECCipher = ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey)
    const noProof = ECelGamal.VoteZKP.generateNoProof(encryptedNoVote, params, uniqueID)

    // verify no vote proof
    const verifiedNoProof: boolean = ECelGamal.VoteZKP.verifyZKP(encryptedNoVote, noProof, params, uniqueID)
    expect(verifiedNoProof).to.be.true
  })
})
