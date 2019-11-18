import { Cipher, SumProof } from '../models';
import { PublicKey } from './models';
import BN = require('bn.js');
export declare const newBN: (n: number) => BN;
export declare function generateSumProof(cipher: Cipher, pk: PublicKey, sk: any, uniqueID: string): SumProof;
export declare function verifySumProof(cipher: Cipher, proof: SumProof, pk: any, uniqueID: string): boolean;
export declare function numbersToString(numbers: Array<BN>): string;
export declare function generateChallenge(q: BN, uniqueID: string, a: BN, b: BN, a1: BN, b1: BN): BN;
