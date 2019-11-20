import { Cipher, Encryption, Helper, KeyShare, KeyShareProof, SystemParameters } from './index'
import BN = require('bn.js')

const web3 = require('web3')
const log = false

export const generateSystemParameters = (p: number, q: number, g: number): SystemParameters => {
  return { p: Helper.newBN(p), q: Helper.newBN(q), g: Helper.newBN(g) }
}

export const generateKeyShares = (params: SystemParameters): KeyShare => {
  const { p, q, g } = params

  // generate first key pair (sk, h)
  // pick a random value in Zq
  const sk: BN = Helper.getSecureRandomValue(q)

  // compute public key share h_: g^sk mod p
  const h: BN = Helper.BNpow(g, sk, p)

  return { h_: h, sk_: sk }
}

export const generateChallenge = (q: BN, uniqueID: string, h_: BN, b: BN): BN => {
  let c = web3.utils.soliditySha3(uniqueID, h_, b)
  c = web3.utils.toBN(c)
  c = c.mod(q)
  return c
}

export const generateKeyGenerationProof = (params: SystemParameters, share: KeyShare, id: string): KeyShareProof => {
  const { p, q, g } = params
  const { h_, sk_ } = share

  // generate a second key pair (a,b)
  // pick a random value from Zq and generate b: g^a mod p
  const a: BN = Helper.getSecureRandomValue(q)
  const b: BN = Helper.BNpow(g, a, p)

  // compute challenge hash(h_, b)
  const c: BN = generateChallenge(q, id, h_, b)

  // compute d = a + c*sk_
  const d: BN = Helper.BNadd(a, Helper.BNmul(c, sk_, q), q)

  return { c: c, d: d }
}

export const verifyKeyGenerationProof = (params: SystemParameters, proof: KeyShareProof, h_: BN, id: string): boolean => {
  const { p, q, g } = params
  const { c, d } = proof

  // recompute b = g^d/h_^c
  const b: BN = Helper.BNdiv(Helper.BNpow(g, d, p), Helper.BNpow(h_, c, p), p)

  // recompute the challenge c = hash(id, h_, b)
  const c_: BN = generateChallenge(q, id, h_, b)
  const hashCheck: boolean = c.eq(c_)

  // verify that: g^d == b * h_^c
  const gPowd: BN = Helper.BNpow(g, d, p)
  const bhPowC: BN = Helper.BNmul(b, Helper.BNpow(h_, c, p), p)
  const dCheck: boolean = gPowd.eq(bhPowC)

  log && console.log('do the hashes match?\t', hashCheck)
  log && console.log('g^d == b * h_^c?\t', dCheck)
  log && console.log()

  return hashCheck && dCheck
}

export const combinePublicKeys = (params: SystemParameters, publicKeyShares: BN[]): BN => {
  return publicKeyShares.reduce((product, share) => Helper.BNmul(product, share, params.p))
}

// NOTE: this should not be used as the distributed secret keys will become "useless"
// it is only used for testing purpose
export const combinePrivateKeys = (params: SystemParameters, privateKeyShares: BN[]): BN => {
  return privateKeyShares.reduce((sum, share) => Helper.BNadd(sum, share, params.q))
}

export const decryptShare = (params: SystemParameters, cipher: Cipher, secretKeyShare: BN): BN => {
  return Helper.BNpow(cipher.a, secretKeyShare, params.p)
}

export const combineDecryptedShares = (params: SystemParameters, cipher: Cipher, decryptedShares: BN[]): BN => {
  const mh = Helper.BNdiv(
    cipher.b,
    decryptedShares.reduce((product, share) => Helper.BNmul(product, share, params.p)),
    params.p
  )

  // TODO: split PublicKey interface into system parameters (p,g,q) and the actual public key (h)
  // (h is not needed here)
  const m = Encryption.decodeMessage(mh, { p: params.p, g: params.g, q: params.q, h: Helper.newBN(1) })

  return m
}
