import { ECCipher, ECParams } from './models';
import { curve } from 'elliptic';
import { SumProof } from '../models';
import BN = require('bn.js');
export declare const generateSumProof: (encryptedVote: ECCipher, params: ECParams, sk: BN, id: string) => SumProof;
export declare const verifySumProof: (encryptedSum: ECCipher, proof: SumProof, params: ECParams, pk: curve.base.BasePoint, id: string) => boolean;
export declare function convertECPointToString(point: any): string;
export declare function convertAllECPointsToString(points: curve.base.BasePoint[]): string;
export declare function generateChallenge(n: BN, id: string, a: curve.base.BasePoint, b: curve.base.BasePoint, a1: curve.base.BasePoint, b1: curve.base.BasePoint): BN;
