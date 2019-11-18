import { ValidVoteProof, Cipher } from '../models';
import { PublicKey } from './models';
export declare const newBN: (n: number) => any;
export declare function generateYesProof(cipher: Cipher, pk: PublicKey, uniqueID: string): ValidVoteProof;
export declare function generateNoProof(cipher: Cipher, pk: PublicKey, uniqueID: string): ValidVoteProof;
export declare function verifyVoteProof(cipher: Cipher, proof: ValidVoteProof, pk: any, uniqueID: string): boolean;
export declare function numbersToString(numbers: Array<any>): string;
export declare function generateChallenge(q: any, uniqueID: any, a: any, b: any, a0: any, b0: any, a1: any, b1: any): any;
