import BN = require('bn.js')

export interface SystemParameters {
  p: BN // prime
  q: BN // prime factor: p = 2*q+1
  g: BN // generator
}

// we ignore the ts-rule: no-explicit-any since we want to be able to check any kind of input
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isSystemParameters(object: any): object is SystemParameters {
  const check1: boolean = object.p !== undefined && object.p instanceof BN
  const check2: boolean = object.q !== undefined && object.q instanceof BN
  const check3: boolean = object.g !== undefined && object.g instanceof BN

  if (!(check1 && check2 && check3)) {
    throw new TypeError(
      `The provided input for type: SystemParameters is not of the required type. Given: ${JSON.stringify(
        object
      )}, Required: {p: BN, q: BN, g: BN}`
    )
  }

  return check1 && check2 && check3
}

export interface KeyPair {
  h: BN
  sk: BN
}

// we ignore the ts-rule: no-explicit-any since we want to be able to check any kind of input
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isKeyPair(object: any): object is KeyPair {
  const check1: boolean = object.h !== undefined && object.h instanceof BN
  const check2: boolean = object.sk !== undefined && object.sk instanceof BN

  if (!(check1 && check2)) {
    throw new TypeError(
      `The provided input for type: KeyPair is not of the required type. Given: ${JSON.stringify(
        object
      )}, Required: {h: BN, sk: BN}`
    )
  }

  return check1 && check2
}

export interface Cipher {
  a: BN
  b: BN
  r?: BN
}

// we ignore the ts-rule: no-explicit-any since we want to be able to check any kind of input
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function isCipher(object: any): object is Cipher {
  const check1: boolean = object.a !== undefined && object.a instanceof BN
  const check2: boolean = object.b !== undefined && object.b instanceof BN
  const rPresent: boolean = object.r !== undefined
  // if r is not present -> use true as default value for check3
  // if r is present -> check if istanceof type BN
  const check3: boolean = rPresent ? object.r instanceof BN : true

  if (!(check1 && check2)) {
    throw new TypeError(
      `The provided input for type: Cipher is not of the required type. Given: ${JSON.stringify(
        object
      )}, Required: {a: BN, b: BN}`
    )
  } else if (rPresent && !check3) {
    throw new TypeError(
      `The provided input for type: Cipher is not of the required type. Given: ${JSON.stringify(
        object
      )}, Required: {a: BN, b: BN, r?: BN}`
    )
  }

  return check1 && check2 && check3
}
