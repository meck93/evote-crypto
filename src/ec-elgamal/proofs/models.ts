import BN = require('bn.js')
import { CurvePoint } from '../index'

export interface KeyGenerationProof {
  c: BN
  d: BN
}

export interface MembershipProof {
  a0: CurvePoint
  a1: CurvePoint
  b0: CurvePoint
  b1: CurvePoint
  c0: BN
  c1: BN
  f0: BN
  f1: BN
}

export interface DecryptionProof {
  a1: CurvePoint
  b1: CurvePoint
  f: BN
  d: CurvePoint
}
