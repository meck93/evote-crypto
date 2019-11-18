import { ECCipher } from './models';
import { curve } from 'elliptic';
import BN = require('bn.js');
export declare const encrypt: (message: curve.base.BasePoint, pubK: curve.base.BasePoint) => ECCipher;
export declare const decrypt: (cipherText: ECCipher, privK: BN) => any;
export declare const homomorphicAdd: (cipher0: ECCipher, cipher1: ECCipher) => ECCipher;
