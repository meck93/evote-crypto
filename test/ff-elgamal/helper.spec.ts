export {}
import { FFelGamal } from '../../src/index'

const { expect } = require('chai')

describe('Finite Field ElGamal Helper', () => {
  it('test', () => {
    // generated test values with http://www.bluetulip.org/2014/programs/primitive.html
    expect(FFelGamal.Helper.getGs(3)).to.eql([2])
    expect(FFelGamal.Helper.getGs(5)).to.eql([2, 3])
    expect(FFelGamal.Helper.getGs(7)).to.eql([3, 5])
    expect(FFelGamal.Helper.getGs(11)).to.eql([2, 6, 7, 8])
    expect(FFelGamal.Helper.getGs(13)).to.eql([2, 6, 7, 11])
    expect(FFelGamal.Helper.getGs(17)).to.eql([3, 5, 6, 7, 10, 11, 12, 14])
    expect(FFelGamal.Helper.getGs(19)).to.eql([2, 3, 10, 13, 14, 15])
    expect(FFelGamal.Helper.getGs(23)).to.eql([5, 7, 10, 11, 14, 15, 17, 19, 20, 21])
    expect(FFelGamal.Helper.getGs(29)).to.eql([2, 3, 8, 10, 11, 14, 15, 18, 19, 21, 26, 27])
    expect(FFelGamal.Helper.getGs(31)).to.eql([3, 11, 12, 13, 17, 21, 22, 24])
    expect(FFelGamal.Helper.getGs(37)).to.eql([2, 5, 13, 15, 17, 18, 19, 20, 22, 24, 32, 35])
    expect(FFelGamal.Helper.getGs(41)).to.eql([6, 7, 11, 12, 13, 15, 17, 19, 22, 24, 26, 28, 29, 30, 34, 35])
    expect(FFelGamal.Helper.getGs(43)).to.eql([3, 5, 12, 18, 19, 20, 26, 28, 29, 30, 33, 34])
    expect(FFelGamal.Helper.getGs(47)).to.eql([
      5,
      10,
      11,
      13,
      15,
      19,
      20,
      22,
      23,
      26,
      29,
      30,
      31,
      33,
      35,
      38,
      39,
      40,
      41,
      43,
      44,
      45,
    ])
  })
})
