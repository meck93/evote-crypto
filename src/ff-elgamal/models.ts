import BN = require('bn.js')

export interface SystemParameters {
  p: BN // prime
  q: BN // prime factor: p = 2*q+1
  g: BN // generator
}

export interface KeyPair {
  h: BN
  sk: BN
}

export interface Cipher {
  a: BN
  b: BN
  r?: BN
}

export interface KeyShare {
  h_: BN
  sk_: BN
  r?: BN
}

export interface ValidVoteProof {
  a0: BN
  a1: BN
  b0: BN
  b1: BN
  c0: BN
  c1: BN
  f0: BN
  f1: BN
}

export interface KeyShareProof {
  c: BN
  d: BN
}

export interface SumProof {
  a1: BN
  b1: BN
  f: BN
  d: BN
}
