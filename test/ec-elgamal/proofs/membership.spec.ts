export {}
import { ECelGamal } from '../../../src/index'
import { ec } from 'elliptic'

import { expect, assert } from 'chai'
import { Cipher, CurvePoint, ValidVoteProof } from '../../../src/ec-elgamal/models'

import { activeCurve } from '../../../src/ec-elgamal/activeCurve'

const log = false

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = activeCurve.curve.g
const noVoteOnCurve = activeCurve.curve.g.neg()

describe('Elliptic Curve ElGamal Vote ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(activeCurve.curve.validate(noVoteOnCurve) && activeCurve.curve.validate(yesVoteOnCurve))
  })

  it('Should generate an elliptic curve valid YES vote proof', () => {
    const keyPair: ec.KeyPair = activeCurve.genKeyPair()
    const publicKey: CurvePoint = keyPair.getPublic() as CurvePoint

    const params: ECelGamal.SystemParameters = {
      p: activeCurve.curve.p,
      g: activeCurve.curve.g,
      n: activeCurve.curve.n,
    }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypted yes vote + generate proof
    log && console.log('YES PROOF\n')
    const encryptedYesVote: Cipher = ECelGamal.Encryption.encrypt(yesVoteOnCurve, publicKey)
    const yesProof: ValidVoteProof = ECelGamal.Proof.Membership.generateYesProof(
      encryptedYesVote,
      params,
      publicKey,
      uniqueID
    )

    // verify yes vote proof
    const verifiedYesProof: boolean = ECelGamal.Proof.Membership.verifyZKP(
      encryptedYesVote,
      yesProof,
      params,
      publicKey,
      uniqueID
    )
    expect(verifiedYesProof).to.be.true
  })

  it('Should generate an elliptic curve valid NO vote proof (FIXME)', () => {
    const keyPair: ec.KeyPair = activeCurve.genKeyPair()
    const publicKey: CurvePoint = keyPair.getPublic() as CurvePoint

    const params: ECelGamal.SystemParameters = {
      p: activeCurve.curve.p,
      g: activeCurve.curve.g,
      n: activeCurve.curve.n,
    }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypt no vote + generate proof
    log && console.log('NO PROOF\n')
    const encryptedNoVote: Cipher = ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey)
    const noProof = ECelGamal.Proof.Membership.generateNoProof(encryptedNoVote, params, publicKey, uniqueID)

    // verify no vote proof
    const verifiedNoProof: boolean = ECelGamal.Proof.Membership.verifyZKP(
      encryptedNoVote,
      noProof,
      params,
      publicKey,
      uniqueID
    )
    expect(verifiedNoProof).to.be.true
  })
})
