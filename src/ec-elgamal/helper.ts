import BN = require('bn.js')

import { Curve, CurvePoint, SystemParameters, SystemParametersSerialized } from './index'
import { instanceOfSystemParametersSerialized } from './models'

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
