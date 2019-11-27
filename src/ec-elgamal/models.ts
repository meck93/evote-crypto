import { curve } from 'elliptic'
import BN = require('bn.js')

//eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface CurvePoint extends curve.short.ShortPoint {}

export interface SystemParameters {
  p: BN // prime
  n: BN // prime factor: p = 2*n+1
  g: CurvePoint // generator
}

export interface SystemParametersSerialized {
  p: string
  n: string
  g: string
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

// TODO: test me
export const instanceOfSystemParametersSerialized = (
  object: any
): object is SystemParametersSerialized => {
  /*const test = (field: string, type: string): boolean => {
    return field in object && typeof object[field] === type
  }*/
  return (
    'p' in object &&
    typeof object.p === 'string' &&
    'n' in object &&
    typeof object.n === 'string' &&
    'g' in object &&
    typeof object.g === 'string'
  )
}
