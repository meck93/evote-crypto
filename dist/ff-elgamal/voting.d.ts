import { PublicKey } from './models';
import { Cipher } from '../models';
export declare const generateYesVote: (pk: PublicKey) => Cipher;
export declare const generateNoVote: (pk: PublicKey) => Cipher;
export declare const addVotes: (votes: Cipher[], pk: PublicKey) => Cipher;
export declare const tallyVotes: (pk: PublicKey, sk: any, votes: Cipher[]) => number;
export declare const getSummary: (total: number, tallyResult: number) => {
    total: number;
    yes: number;
    no: number;
};
