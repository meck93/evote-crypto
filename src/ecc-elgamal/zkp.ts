const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const BN = require('bn.js')
import { EccElGamal } from '../index'
import { ValidVoteProof } from '../models'

// TODO: implement me (based on ff elgamal zkp)

const printConsole = false

export function createZKP(message: any, pubK: any): ValidVoteProof {
  const alpha = EccElGamal.getSecureRandomValue()
  const r1 = EccElGamal.getSecureRandomValue()
  const d1 = EccElGamal.getSecureRandomValue()
  const w = EccElGamal.getSecureRandomValue()

  const cipher = EccElGamal.encrypt(message, pubK)

  const x = cipher.c1
  const y = cipher.c2

  const xTd1 = x.mul(d1)
  const gTr1 = ec.curve.g.mul(r1)
  const a1 = gTr1.add(xTd1)
  printConsole && console.log('a1 is on curve?', ec.curve.validate(a1))

  const pubKTr1 = pubK.mul(r1)
  const yG = y.add(ec.curve.g)
  const yGTd1 = yG.mul(d1)
  const b1 = pubKTr1.add(yGTd1)
  printConsole && console.log('b1 is on the curve?', ec.curve.validate(b1))

  const a2 = ec.curve.g.mul(w)
  printConsole && console.log('a2 is on the curve?', ec.curve.validate(a2))

  const b2 = pubK.mul(w)
  printConsole && console.log('b2 is on the curve?', ec.curve.validate(b2))

  // TODO: change this ID with real ethereum address
  const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

  // TODO: fix the challenge generation such that the hash function output is always valid
  const challenge = generateChallenge(uniqueID, x, y, a1, a2, b1, b2)
  printConsole &&
    console.log('challence is greater than n', challenge.gt(ec.curve.n), 'c is greater than 1', challenge.gt(1))

  let d2 = challenge.sub(d1).mod(ec.curve.n)
  printConsole && console.log('d2:', d2.isNeg(), 'c:', challenge.isNeg(), 'd1:', d1.isNeg())

  const intermediate = alpha.mul(d2).mod(ec.curve.n)
  const r2 = w.sub(intermediate)

  return { x, y, a1, a2, b1, b2, d1, d2, r1, r2, challenge }
}

export function verifyZKP(proof: ValidVoteProof, pubK: any): boolean {
  const { x, y, a1, a2, b1, b2, d1, d2, r1, r2, challenge } = proof

  // validation of the hash - digest == hash(challenge)
  const d1d2 = d1.add(d2).mod(ec.curve.n)
  printConsole && console.log('Is the hash the same?', d1d2.eq(challenge))

  // validation of a1
  const gTr1 = ec.curve.g.mul(r1)
  const xTd1 = x.mul(d1)
  const gTr1xTd1 = gTr1.add(xTd1)
  printConsole && console.log('Is a1 the same?', gTr1xTd1.eq(a1))

  // validation of b1
  const pubKTr1 = pubK.mul(r1)
  const yG = y.add(ec.curve.g)
  const yGTd1 = yG.mul(d1)
  const pubKTr1yGTd1 = pubKTr1.add(yGTd1)
  printConsole && console.log('Is b1 the same?', pubKTr1yGTd1.eq(b1))

  // validation of a2
  const gTr2 = ec.curve.g.mul(r2)
  const xTd2 = x.mul(d2)
  const gTr2xTd2 = gTr2.add(xTd2)
  printConsole && console.log('Is a2 the same?', gTr2xTd2.eq(a2))
  // console.log('a2', a2.getX().toString('hex'), a2.getY().toString('hex'))
  // console.log('a2', gTr2xTd2.getX().toString('hex'), gTr2xTd2.getY().toString('hex'))

  // validation of b2
  const pubKTr2 = pubK.mul(r2)
  const generator_inverted = ec.curve.g.neg()
  const yMinusG = y.add(generator_inverted)
  const yMinusGTd2 = yMinusG.mul(d2)
  const pubKTr2yMinusGTd2 = pubKTr2.add(yMinusGTd2)
  printConsole && console.log('Is b2 the same?', pubKTr2yMinusGTd2.eq(b2))

  // TODO: implement how the verify function should calculate the final result
  return true
}

export function generateChallenge(uniqueID: any, c1: any, c2: any, a1: any, a2: any, b1: any, b2: any) {
  const pointsAsString = convertAllECPointsToString([c1, c2, a1, a2, b1, b2])
  const input = uniqueID + pointsAsString

  const challenge = ec
    .hash()
    .update('test')
    .digest('hex')

  return new BN(challenge, 'hex')
  // return new BN(10, 'hex')
}

export function convertECPointToString(point: any) {
  const pointAsJSON = point.toJSON()
  const Px = pointAsJSON[0].toString('hex')
  const Py = pointAsJSON[1].toString('hex')
  return Px + Py
}

export function convertAllECPointsToString(points: any[]) {
  let asString = ''
  for (const point of points) {
    asString += convertECPointToString(point)
  }
  return asString
}
