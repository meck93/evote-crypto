export interface PublicKey {
  p: any // prime
  g: any // generator
  h: any
}

export interface Cipher {
  c1: any
  c2: any
}

export interface Summary {
  total: number
  yes: number
  no: number
}
