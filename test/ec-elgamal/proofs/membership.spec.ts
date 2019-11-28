import { assert, expect } from 'chai'
import { ECelGamal } from '../../../src/index'

const log = false

// fixed constants for values 1 -> generator and 0 -> generator^-1
const yesVoteOnCurve = ECelGamal.Curve.g
const noVoteOnCurve = ECelGamal.Curve.g.neg()

describe('Elliptic Curve ElGamal Vote ZKP', () => {
  it('Points that encode the plaintexts should lie on the curve', function() {
    assert(ECelGamal.Curve.validate(noVoteOnCurve) && ECelGamal.Curve.validate(yesVoteOnCurve))
  })

  it('Should generate an elliptic curve valid YES vote proof', () => {
    const { h: publicKey } = ECelGamal.SystemSetup.generateKeyPair()

    const params: ECelGamal.SystemParameters = {
      p: ECelGamal.Curve.p,
      g: ECelGamal.Curve.g,
      n: ECelGamal.Curve.n,
    }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypted yes vote + generate proof
    log && console.log('YES PROOF\n')
    const encryptedYesVote: ECelGamal.Cipher = ECelGamal.Encryption.encrypt(
      yesVoteOnCurve,
      publicKey
    )
    const yesProof: ECelGamal.Proof.MembershipProof = ECelGamal.Proof.Membership.generateYesProof(
      encryptedYesVote,
      params,
      publicKey,
      uniqueID
    )

    // verify yes vote proof
    const verifiedYesProof: boolean = ECelGamal.Proof.Membership.verify(
      encryptedYesVote,
      yesProof,
      params,
      publicKey,
      uniqueID
    )
    expect(verifiedYesProof).to.be.true
  })

  it('Should generate an elliptic curve valid NO vote proof (FIXME)', () => {
    const { h: publicKey } = ECelGamal.SystemSetup.generateKeyPair()

    const params: ECelGamal.SystemParameters = {
      p: ECelGamal.Curve.p,
      g: ECelGamal.Curve.g,
      n: ECelGamal.Curve.n,
    }
    const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

    // encrypt no vote + generate proof
    log && console.log('NO PROOF\n')
    const encryptedNoVote: ECelGamal.Cipher = ECelGamal.Encryption.encrypt(noVoteOnCurve, publicKey)
    const noProof = ECelGamal.Proof.Membership.generateNoProof(
      encryptedNoVote,
      params,
      publicKey,
      uniqueID
    )

    // verify no vote proof
    const verifiedNoProof: boolean = ECelGamal.Proof.Membership.verify(
      encryptedNoVote,
      noProof,
      params,
      publicKey,
      uniqueID
    )
    expect(verifiedNoProof).to.be.true
  })
})
