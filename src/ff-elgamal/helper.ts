const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

// get all integers from 0 (inclusive) to a (exclusive)
const range = (a: any): any[] => Array.from(Array(a).keys())


// calculate q given p
export const getQofP = (p: any) => (p - 1) / 2

// get all primes that have a q = (p-1)/2
const getPCandidates = (primes: any) =>
  primes.reduce((previous: any, current: any) => {
    return primes.includes(getQofP(current)) ? [...previous, current] : previous
  }, [])

// get all generators g given a prime
// FIXME
const getGCandidates = (prime: any) =>
  range(prime).reduce((previous: any, current: any) => {
    return Math.pow(current, getQofP(prime)) % prime === 1 ? [...previous, current] : previous
  }, [])

// FIXME
export const getGs = (p: number): number[] => {
  // source: https://asecuritysite.com/encryption/pickg
  const g: number[] = []
  for (let i = 1; i < p; i++) {
    let exp = 1
    let next = i % p

    while (next !== 1) {
      next = (next * i) % p
      exp += 1
    }

    if (exp === p - 1) {
      g.push(i)
    }
  }

  return g
}

export const findSuitableInputs = () => {
  const prime = 11
  console.log('p', prime)
  console.log('p candidates', getPCandidates(primes))
  console.log('g candidates', getGCandidates(prime))
  console.log()
}


// const crypto = require('crypto')

// export const getSecureRandomValue = (): any => {
//   const RAND_SIZE_BYTES = 32

//   // TODO: Fix upper limit to p-2
//   const UPPER_BOUND_RANDOM = null

//   let randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
//   let randomValue = new BN(randomBytes)

//   // ensure that the random value is in range [1,n-1]
//   while (!randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(1)) {
//     randomBytes = crypto.randomBytes(RAND_SIZE_BYTES)
//     randomValue = new BN(randomBytes, 'hex')
//   }
//   return randomValue
// }
