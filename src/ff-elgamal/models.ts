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
