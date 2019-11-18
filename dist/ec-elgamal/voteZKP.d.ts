import { ValidVoteProof } from '../models';
import { ECParams, ECCipher } from './models';
import BN = require('bn.js');
export declare function generateYesProof(encryptedVote: ECCipher, params: ECParams, id: string): ValidVoteProof;
export declare function generateNoProof(encryptedVote: ECCipher, params: ECParams, id: string): ValidVoteProof;
export declare function verifyZKP(encryptedVote: ECCipher, proof: ValidVoteProof, params: ECParams, id: string): boolean;
export declare function generateChallenge(n: BN, id: any, c1: any, c2: any, a1: any, a2: any, b1: any, b2: any): any;
export declare function convertECPointToString(point: any): any;
export declare function convertAllECPointsToString(points: any[]): string;
