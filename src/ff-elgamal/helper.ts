// check if a given number is prime
export const isPrime = (num: number): boolean => {
  for (let i = 2; i <= Math.sqrt(num); i++) {
    if (Math.floor(num / i) == num / i) {
      return false
    }
  }
  return true
}

// get all primitive roots of a given number
// only works for prime numbers
// TODO: implement for non-prime numbers
export const getPrimitiveRoots = (n: number): number[] => {
  if (!isPrime(n)) {
    return []
  }

  // source: https://asecuritysite.com/encryption/pickg
  const g: number[] = []
  for (let i = 1; i < n; i++) {
    let exp = 1
    let next = i % n

    while (next !== 1) {
      next = (next * i) % n
      exp += 1
    }

    if (exp === n - 1) {
      g.push(i)
    }
  }

  return g
}

// calculate q given p (for p < 2)
// TODO: maybe check if p is actually prime
export const getQofP = (p: number): number => (p > 1 ? (p - 1) / 2 : -1)

// q is valid if it is prime
export const isQValid = (q: number): boolean => (q > 1 ? isPrime(q) : false)

// g is valid if:
// - g != 1
// - q != q
// - g^q mod p == 1
export const isGValid = (g: number, p: number): boolean => {
  return g !== 1 && g !== getQofP(p) && g ** getQofP(p) % p === 1
}

// get all primes that have a q = (p-1)/2 that is prime given a list of primes
export const getPCandidates = (primes: number[]): number[] =>
  primes.reduce((previous: number[], current: number) => {
    return isQValid(getQofP(current)) ? [...previous, current] : previous
  }, [])

// get all generators g of q given a prime p
export const getGCandidates = (p: number): number[] =>
  getPrimitiveRoots(getQofP(p)).reduce((previous: number[], current: number) => {
    return isGValid(current, p) ? [...previous, current] : previous
  }, [])
