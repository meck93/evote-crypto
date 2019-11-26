import { curve } from 'elliptic'
import BN = require('bn.js')

//eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface CurvePoint extends curve.short.ShortPoint {}

export interface SystemParameters {
  p: BN
  n: BN
  g: CurvePoint
}

export interface KeyPair {
  h: CurvePoint
  sk: BN
}

export interface Cipher {
  a: CurvePoint
  b: CurvePoint
  r?: BN
}

export interface ECParams {
  p: BN
  n: BN // prime factor: p = 2*n+1
  g: CurvePoint // generator
  h: CurvePoint
}

export interface ECParamsTransfer {
  p: BN
  n: BN // prime factor: p = 2*n+1
  g: string // generator
  h: string
}

export interface ValidVoteProof {
  a0: CurvePoint
  a1: CurvePoint
  b0: CurvePoint
  b1: CurvePoint
  c0: BN
  c1: BN
  f0: BN
  f1: BN
}

export interface KeyShareProof {
  c: BN
  d: BN
}
