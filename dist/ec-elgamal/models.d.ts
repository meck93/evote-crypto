import { curve } from 'elliptic';
import BN = require('bn.js');
export interface ECCipher {
    a: curve.base.BasePoint;
    b: curve.base.BasePoint;
    r?: BN;
}
export interface ECParams {
    p: BN;
    n: BN;
    g: curve.base.BasePoint;
    h: curve.base.BasePoint;
}
export interface ECParamsTransfer {
    p: BN;
    n: BN;
    g: string;
    h: string;
}
