import BN = require('bn.js')
import crypto = require('crypto')

import { Curve, CurvePoint, SystemParameters, SystemParametersSerialized } from './index'
import { instanceOfSystemParametersSerialized } from './models'

export const getSecureRandomValue = (n: BN): BN => {
  const byteSize = 32
  const one = new BN(1, 10)
  const UPPER_BOUND_RANDOM: BN = n.sub(one)

  let randomBytes: Buffer = crypto.randomBytes(byteSize)
  let randomValue: BN = new BN(randomBytes)

  // ensure that the random value is in range [1,n-1]
  while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
    randomBytes = crypto.randomBytes(byteSize)
    randomValue = new BN(randomBytes)
  }
  return randomValue
}

export const newBN = (n: number, base = 10): BN => new BN(n, base)

export const BNadd = (a: BN, b: BN, mod: BN): BN => a.add(b).mod(mod)
export const BNsub = (a: BN, b: BN, mod: BN): BN => a.sub(b).mod(mod)
export const BNmul = (a: BN, b: BN, mod: BN): BN => a.mul(b).mod(mod)

export const ECpow = (a: CurvePoint, b: BN): CurvePoint => a.mul(b) as CurvePoint
export const ECmul = (a: CurvePoint, b: CurvePoint): CurvePoint => a.add(b) as CurvePoint
export const ECdiv = (a: CurvePoint, b: CurvePoint): CurvePoint => a.add(b.neg()) as CurvePoint

export const curvePointToString = (point: CurvePoint): string => {
  const pointAsJSON = point.toJSON()
  const Px = (pointAsJSON[0] as BN).toString('hex')
  const Py = (pointAsJSON[1] as BN).toString('hex')
  return Px + Py
}

export const curvePointsToString = (points: CurvePoint[]): string => {
  let asString = ''
  for (const point of points) {
    asString += curvePointToString(point)
  }
  return asString
}

export const serializeBN = (bn: BN): string => {
  return bn.toString('hex')
}

export const deserializeBN = (bn: string): BN => {
  return new BN(bn, 'hex')
}

// https://github.com/indutny/elliptic/blob/71e4e8e2f5b8f0bdbfbe106c72cc9fbc746d3d60/test/curve-test.js#L265
export const serializeCurvePoint = (point: CurvePoint): string => {
  return point.encode('hex', false)
}

export const deserializeCurvePoint = (point: CurvePoint | string): CurvePoint => {
  if (typeof point !== 'string') {
    return point
  }
  return Curve.decodePoint(point, 'hex')
}

export const serializeSystemParameters = (params: SystemParameters): SystemParametersSerialized => {
  return {
    p: serializeBN(params.p),
    n: serializeBN(params.n),
    g: serializeCurvePoint(params.g),
  }
}

export const deserializeParams = (
  params: SystemParameters | SystemParametersSerialized
): SystemParameters => {
  if (!instanceOfSystemParametersSerialized(params)) {
    return params
  }
  return {
    p: deserializeBN(params.p), // BN
    n: deserializeBN(params.n), // BN
    g: deserializeCurvePoint(params.g),
  }
}
