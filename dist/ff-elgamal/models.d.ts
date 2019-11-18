import BN = require('bn.js');
export interface PublicKey {
    p: BN;
    q: BN;
    g: BN;
    h: BN;
}
export interface KeyShare {
    h_: BN;
    sk_: BN;
    r?: BN;
}
export interface SystemParameters {
    p: BN;
    q: BN;
    g: BN;
}
