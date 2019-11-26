import BN = require('bn.js')
import { ec as EC } from 'elliptic'

import { activeCurve } from './activeCurve'
import { SystemParameters, CurvePoint, KeyPair } from './models'
import { Helper } from './index'

export const generateSystemParameters = (): SystemParameters => {
  return { p: activeCurve.curve.p, n: activeCurve.curve.n, g: activeCurve.curve.g }
}

export const generateKeyPair = (): KeyPair => {
  const keyPair: EC.KeyPair = activeCurve.genKeyPair()
  const sk: BN = keyPair.getPrivate()
  const h: CurvePoint = keyPair.getPublic() as CurvePoint
  return { h, sk }
}

export const combinePublicKeys = (publicKeyShares: CurvePoint[]): CurvePoint => {
  return publicKeyShares.reduce((product, share) => Helper.ECmul(product, share))
}

// combines multiple private key shares to one private key
// NOTE: this should not be used as the distributed secret keys will become "useless"
//       it is only used for testing purpose
export const combinePrivateKeys = (params: SystemParameters, privateKeyShares: BN[]): BN => {
  return privateKeyShares.reduce((sum, share) => Helper.BNadd(sum, share, params.n))
}
