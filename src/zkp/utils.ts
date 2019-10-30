import { Proof } from '../models'

export function serializeCurvePoint(point: any) {
  const str = JSON.stringify(point)
  const c1 = JSON.parse(str)[0]
  const c2 = JSON.parse(str)[1]
  return [c1, c2]
}

export function serializeAndPrintProof(proof: Proof) {
  console.log('x: \n', serializeCurvePoint(proof.x))
  console.log('y: \n', serializeCurvePoint(proof.y))
  console.log('a1: \n', serializeCurvePoint(proof.a1))
  console.log('a2: \n', serializeCurvePoint(proof.a2))
  console.log('b1: \n', serializeCurvePoint(proof.b1))
  console.log('b2: \n', serializeCurvePoint(proof.b2))

  console.log('d1: \n', proof.d1.toJSON())
  console.log('d2: \n', proof.d2.toJSON())
  console.log('r1: \n', proof.r1.toJSON())
  console.log('r2: \n', proof.r2.toJSON())
  console.log('c: \n', proof.challenge.toJSON())
}
