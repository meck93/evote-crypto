import BN = require('bn.js')
import { CurvePoint } from '../index';

export interface DecryptionProof {
  a1: CurvePoint
  b1: CurvePoint
  f: BN
  d: CurvePoint
}
