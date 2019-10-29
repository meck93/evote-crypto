const BN = require('bn.js')
import { ElGamal } from '../index'
import { Proof, Cipher } from '../models'
import { PublicKey } from '../elgamal/models'

const random = require('random')

const printConsole = true

export function createZKP(encryptedMessage: Cipher, pk: PublicKey): Proof {
  // const alpha = new BN(random.int(1, pk.p - 2), 10)
  const alpha = new BN(2, 10)
  printConsole && console.log('alpha', alpha)
  // const r1 = new BN(random.int(1, pk.p - 2), 10)
  const r1 = new BN(2, 10)
  printConsole && console.log('r1', r1)
  // const d1 = new BN(random.int(1, pk.p - 2), 10)
  const d1 = new BN(2, 10)
  printConsole && console.log('d1', d1)
  // const w = new BN(random.int(1, pk.p - 2), 10)
  const w = new BN(2, 10)
  printConsole && console.log('w', w)

  const x = encryptedMessage.c1
  console.log('x', x)
  const y = encryptedMessage.c2
  console.log('y', y)

  const xPowd1 = x.pow(d1).mod(pk.p)
  const gPowr1 = pk.g.pow(r1).mod(pk.p)
  const a1 = xPowd1.mul(gPowr1).mod(pk.p)
  // printConsole && console.log('a1', a1)

  const hPowr1 = pk.h.pow(r1).mod(pk.p)
  const yG = y.mul(pk.g).mod(pk.p)
  const yGPowd1 = yG.pow(d1).mod(pk.p)
  const b1 = hPowr1.mul(yGPowd1).mod(pk.p)
  // printConsole && console.log('b1', b1)

  const a2 = pk.g.pow(w).mod(pk.p)
  printConsole && console.log('a2', a2)

  const b2 = pk.h.pow(w).mod(pk.p)
  printConsole && console.log('b2', b2)

  // TODO: change this ID with real ethereum address
  const uniqueID = '0xAd4E7D8f03904b175a1F8AE0D88154f329ac9329'

  // TODO: fix the challenge generation such that the hash function output is always valid
  const challenge = generateChallenge(uniqueID, x, y, a1, a2, b1, b2)
  printConsole &&
    console.log('challence is greater than p', challenge.gt(pk.p), 'c is greater than 1', challenge.gt(new BN(1, 10)))

  const d1_inverse = inverseAdditiveModulo(d1, pk.p)
  console.log('d1', d1)
  console.log('d1_inverse', d1_inverse)

  let d2 = challenge.add(d1_inverse).mod(pk.p)
  printConsole && console.log('d2:', d2.isNeg(), 'c:', challenge.isNeg(), 'd1:', d1.isNeg())

  console.log('d2', d2)

  const intermediate = alpha.mul(d2).mod(pk.p)
  console.log('inter', intermediate)

  const intermedia_inverse = inverseAdditiveModulo(intermediate, pk.p)
  console.log('inter inverse', intermedia_inverse)

  const r2 = w.add(intermedia_inverse).mod(pk.p)
  console.log('r2', r2)

  return { x, y, a1, a2, b1, b2, d1, d2, r1, r2, challenge }
}

export function verifyZKP(proof: Proof, pk: any): boolean {
  const { x, y, a1, a2, b1, b2, d1, d2, r1, r2, challenge } = proof

  // validation of the hash - digest == hash(challenge)
  const d1d2 = d1.add(d2).mod(pk.p)
  printConsole && console.log('Is the hash the same?', d1d2.eq(challenge))

  // validation of a1
  const gPowr1 = pk.g.pow(r1).mod(pk.p)
  const xPowd1 = x.pow(d1).mod(pk.p)
  const gPowr1xPowd1 = gPowr1.mul(xPowd1).mod(pk.p)
  // printConsole && console.log('Is a1 the same?', gPowr1xPowd1.eq(a1))

  // validation of b1
  const hPowr1 = pk.h.pow(r1).mod(pk.p)
  const yG = y.mul(pk.g).mod(pk.p)
  const yGPowd1 = yG.pow(d1).mod(pk.p)
  const hPowr1yGPowd1 = hPowr1.mul(yGPowd1).mod(pk.p)
  // printConsole && console.log('Is b1 the same?', hPowr1yGPowd1.eq(b1))

  // validation of a2
  const gPowr2 = pk.g.pow(r2).mod(pk.p)
  console.log('g^r2', gPowr2)
  const xPowd2 = x.pow(d2).mod(pk.p)
  console.log('x^d2', xPowd2)
  const gPowr2xPowd2 = gPowr2.mul(xPowd2).mod(pk.p)
  printConsole && console.log('Is a2 the same?', gPowr2xPowd2.eq(a2), gPowr2xPowd2, a2)
  // console.log('a2', a2.getX().toString('hex'), a2.getY().toString('hex'))
  // console.log('a2', gTr2xTd2.getX().toString('hex'), gTr2xTd2.getY().toString('hex'))

  // validation of b2
  const hPowR2 = pk.h.pow(r2).mod(pk.p)
  const generator_inverted = pk.g.invm(pk.p)
  const yDivG = y.mul(generator_inverted).mod(pk.p)
  const yDivGPowd2 = yDivG.pow(d2).mod(pk.p)
  const hPowR2yDivGPowd2 = hPowR2.mul(yDivGPowd2).mod(pk.p)
  printConsole && console.log('Is b2 the same?', hPowR2yDivGPowd2.eq(b2), hPowR2yDivGPowd2, b2)

  // TODO: implement how the verify function should calculate the final result
  return true
}

export function generateChallenge(uniqueID: any, c1: any, c2: any, a1: any, a2: any, b1: any, b2: any) {
  const pointsAsString = convertAllECPointsToString([c1, c2, a1, a2, b1, b2])
  const input = uniqueID + pointsAsString

  //   const challenge = ec
  //     .hash()
  //     .update('test')
  //     .digest('hex')

  //   return new BN(challenge, 'hex')
  return new BN(6, 10)
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
