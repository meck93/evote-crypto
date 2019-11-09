import BN = require('bn.js')

export interface PublicKey {
  p: BN // prime
  q: BN // prime factor: p = 2*q+1
  g: BN // generator
  h: BN
}

export interface KeyShare {
  h_: BN
  sk_: BN
  r?: BN
}

export interface SystemParameters {
  p: BN
  q: BN
  g: BN
}
