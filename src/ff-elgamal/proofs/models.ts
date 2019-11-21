import BN = require('bn.js')

export interface KeyGenerationProof {
  c: BN
  d: BN
}

export interface MembershipProof {
  a0: BN
  a1: BN
  b0: BN
  b1: BN
  c0: BN
  c1: BN
  f0: BN
  f1: BN
}

export interface DecryptionProof {
  a1: BN
  b1: BN
  f: BN
  d: BN
}
