import { curve } from 'elliptic'
import BN = require('bn.js')

export interface ECCipher {
  a: curve.base.BasePoint
  b: curve.base.BasePoint
  r?: BN
}

export interface ECParams {
  p: BN
  n: BN // prime factor: p = 2*n+1
  g: curve.base.BasePoint // generator
  h: curve.base.BasePoint
}
