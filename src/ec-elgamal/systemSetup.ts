import BN = require('bn.js')
import { ec as EC } from 'elliptic'

import { SystemParameters, CurvePoint, KeyPair } from './models'
import { Helper, Curve } from './index'
import { curveDefinition } from './curve'

export const generateSystemParameters = (): SystemParameters => {
  return { p: Curve.p, n: Curve.n, g: Curve.g }
}

export const generateKeyPair = (): KeyPair => {
  const keyPair: EC.KeyPair = curveDefinition.genKeyPair()
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
