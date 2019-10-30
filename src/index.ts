import { Cipher, Summary, Proof } from './models'
export { Cipher, Summary, Proof }

// ElGamal
import * as ElGamal from './elgamal'
import * as ElGamalVoting from './elgamal/voting'
import { PublicKey } from './elgamal/models'

export { ElGamal, ElGamalVoting, PublicKey }

// ECC ElGamal
import * as EccElGamal from './ecc-elgamal'
import * as EccElGamalVoting from './ecc-elgamal/voting'
import * as EccElGamalZKP from './zkp'

export { EccElGamal, EccElGamalVoting, EccElGamalZKP }

// ECC Utils
export { serializeCurvePoint, serializeAndPrintProof } from './zkp/utils'
