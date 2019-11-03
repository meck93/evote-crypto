import { getQofP } from "."

const primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

// get all integers from 0 (inclusive) to a (exclusive)
const range = (a: any): any[] => Array.from(Array(a).keys())

// get all primes that have a q = (p-1)/2
const getPCandidates = (primes: any) =>
  primes.reduce((previous: any, current: any) => {
    return primes.includes(getQofP(current)) ? [...previous, current] : previous
  }, [])

// get all generators g given a prime
const getGCandidates = (prime: any) =>
  range(prime).reduce((previous: any, current: any) => {
    return Math.pow(current, getQofP(prime)) % prime === 1 ? [...previous, current] : previous
  }, [])

export const findSuitableInputs = () => {
  const prime = 11
  console.log('p', prime)
  console.log('p candidates', getPCandidates(primes))
  console.log('g candidates', getGCandidates(prime))
  console.log()
}
