export {}
import { FFelGamal } from '../../src/index'

import { primes as primes2 } from './primes.spec'

const { expect } = require('chai')
const Helper = FFelGamal.Helper

// all prime numbers up to 100
const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

describe('Finite Field ElGamal Helper', () => {
  it('should check if a given number is prime', () => {
    for (const prime of primes) {
      expect(Helper.isPrime(prime)).to.be.true
    }

    // print all primes up to 100'000
    /*
    let p = ''
    for (let i = 2; i <= 100000; i++) {
      if(Helper.isPrime(i)) {
        p += (i + ',')
      }
    }
    console.log(p)
    */
  })

  it('should get all primitive roots given n', () => {
    // values from https://en.wikipedia.org/wiki/Primitive_root_modulo_n
    // calculate them here www.bluetulip.org/2014/programs/primitive.html
    const values = [
      //{ n: 2, roots: [1] },
      { n: 3, roots: [2] },
      //{ n: 4, roots: [3] },
      { n: 5, roots: [2, 3] },
      //{ n: 6, roots: [5] },
      { n: 7, roots: [3, 5] },
      //{ n: 8, roots: [] },
      //{ n: 9, roots: [2, 5] },
      //{ n: 10, roots: [3, 7] },
      { n: 11, roots: [2, 6, 7, 8] },
      //{ n: 12, roots: [] },
      { n: 13, roots: [2, 6, 7, 11] },
      //{ n: 14, roots: [3, 5] },
      //{ n: 15, roots: [] },
      //{ n: 16, roots: [] },
      { n: 17, roots: [3, 5, 6, 7, 10, 11, 12, 14] },
      //{ n: 18, roots: [5 ,11] },
      { n: 19, roots: [2, 3, 10, 13, 14, 15] },
      //{ n: 20, roots: [] },
      //{ n: 21, roots: [] },
      //{ n: 22, roots: [7, 13, 17, 19] },
      { n: 23, roots: [5, 7, 10, 11, 14, 15, 17, 19, 20, 21] },
      { n: 29, roots: [2, 3, 8, 10, 11, 14, 15, 18, 19, 21, 26, 27] },
      { n: 31, roots: [3, 11, 12, 13, 17, 21, 22, 24] },
      { n: 37, roots: [2, 5, 13, 15, 17, 18, 19, 20, 22, 24, 32, 35] },
      { n: 41, roots: [6, 7, 11, 12, 13, 15, 17, 19, 22, 24, 26, 28, 29, 30, 34, 35] },
      { n: 43, roots: [3, 5, 12, 18, 19, 20, 26, 28, 29, 30, 33, 34] },
      { n: 47, roots: [5, 10, 11, 13, 15, 19, 20, 22, 23, 26, 29, 30, 31, 33, 35, 38, 39, 40, 41, 43, 44, 45] },
      { n: 53, roots: [2, 3, 5, 8, 12, 14, 18, 19, 20, 21, 22, 26, 27, 31, 32, 33, 34, 35, 39, 41, 45, 48, 50, 51] },
      { n: 59, roots: [2, 6, 8, 10, 11, 13, 14, 18, 23, 24, 30, 31, 32, 33, 34, 37, 38, 39, 40, 42, 43, 44, 47, 50, 52, 54, 55, 56] },
      { n: 61, roots: [2, 6, 7, 10, 17, 18, 26, 30, 31, 35, 43, 44, 51, 54, 55, 59] },
      { n: 67, roots: [2, 7, 11, 12, 13, 18, 20, 28, 31, 32, 34, 41, 44, 46, 48, 50, 51, 57, 61, 63] },
      { n: 71, roots: [7, 11, 13, 21, 22, 28, 31, 33, 35, 42, 44, 47, 52, 53, 55, 56, 59, 61, 62, 63, 65, 67, 68, 69] },
      { n: 73, roots: [5, 11, 13, 14, 15, 20, 26, 28, 29, 31, 33, 34, 39, 40, 42, 44, 45, 47, 53, 58, 59, 60, 62, 68] },
      { n: 79, roots: [3, 6, 7, 28, 29, 30, 34, 35, 37, 39, 43, 47, 48, 53, 54, 59, 60, 63, 66, 68, 70, 74, 75, 77] },
    ]

    for (const value of values) {
      expect(Helper.getPrimitiveRoots(value.n)).to.eql(value.roots)
    }
  })

  it('should calculate q given p', () => {
    expect(Helper.getQofP(-2)).to.eql(-1)
    expect(Helper.getQofP(0)).to.eql(-1)
    expect(Helper.getQofP(-1)).to.eql(-1)
    expect(Helper.getQofP(1)).to.eql(-1)
    expect(Helper.getQofP(2)).to.eql(0.5)
    expect(Helper.getQofP(3)).to.eql(1)
    expect(Helper.getQofP(4)).to.eql(1.5)
    expect(Helper.getQofP(5)).to.eql(2)
    expect(Helper.getQofP(6)).to.eql(2.5)
    expect(Helper.getQofP(7)).to.eql(3)
    expect(Helper.getQofP(8)).to.eql(3.5)
    expect(Helper.getQofP(9)).to.eql(4)
    expect(Helper.getQofP(10)).to.eql(4.5)
    expect(Helper.getQofP(11)).to.eql(5)
    expect(Helper.getQofP(13)).to.eql(6)
    expect(Helper.getQofP(17)).to.eql(8)
    expect(Helper.getQofP(19)).to.eql(9)
  })

  it('should validate q', () => {
    expect(Helper.isQValid(-1)).to.false
    expect(Helper.isQValid(0)).to.false
    expect(Helper.isQValid(1)).to.false
    expect(Helper.isQValid(2)).to.true
    expect(Helper.isQValid(3)).to.true
    expect(Helper.isQValid(4)).to.false
    expect(Helper.isQValid(5)).to.true
  })

  it('should validate g given p', () => {
    const values = [
      { p: 7, gs: [2] },
      { p: 11, gs: [3] },
      { p: 23, gs: [2, 6, 8] },
      { p: 59, gs: [3] },
      { p: 167, gs: [2, 8, 32] },
      { p: 263, gs: [2, 8, 128] },
      { p: 347, gs: [11, 44] },
      { p: 359, gs: [2, 8, 32] },
      { p: 839, gs: [2] },
      { p: 887, gs: [2] },
      { p: 983, gs: [2] },
      { p: 1319, gs: [2] },
      { p: 2039, gs: [2] },
    ]

    for (const value of values) {
      for (const g of value.gs) {
        expect(Helper.isGValid(g, value.p)).to.true
      }
    }

    expect(Helper.isGValid(3, 7)).to.false
  })

  it('should get candidate values for p (having a q that is prime)', () => {
    expect(Helper.getPCandidates(primes)).to.eql([5, 7, 11, 23, 47, 59, 83])
  })

  it('should get candidate values for g given p', () => {
    const values = [
      { p: 7, gs: [2] },
      { p: 11, gs: [3] },
      { p: 23, gs: [2, 6, 8] },
      { p: 59, gs: [3] }, // next ones over 100: 167, 263, ...
    ]

    for (const value of values) {
      expect(Helper.getGCandidates(value.p)).to.eql(value.gs)
    }

    /*
    // get candidate gs for all primes up to 10'000
    let index = 0;
    for (const prime of primes2) {
      const gs = Helper.getGCandidates(prime)
      gs.length > 0 && console.log(prime, gs)
      index++ % 100 === 0 && console.log(prime, gs)
    }
    */
  })

  xit('should print suitable values', () => {
    const prime = 11
    console.log('p candidates', Helper.getPCandidates(primes).toString())
    console.log()
    console.log('p', prime)
    console.log('g candidates', Helper.getGCandidates(prime).toString())
  })
})
