"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var helper_1 = require("./helper");
var encryption_1 = require("./encryption");
var web3 = require('web3');
exports.generateSystemParameters = function (p, q, g) {
    return { p: helper_1.newBN(p), q: helper_1.newBN(q), g: helper_1.newBN(g) };
};
exports.generateKeyShares = function (params) {
    var p = params.p, q = params.q, g = params.g;
    var sk = helper_1.getSecureRandomValue(q);
    var h = helper_1.BNpow(g, sk, p);
    return { h_: h, sk_: sk };
};
exports.generateKeyGenerationProof = function (params, share, id) {
    var p = params.p, q = params.q, g = params.g;
    var h_ = share.h_, sk_ = share.sk_;
    var a = helper_1.getSecureRandomValue(q);
    var b = helper_1.BNpow(g, a, p);
    var c = exports.generateChallenge(q, id, h_, b);
    var d = helper_1.BNadd(a, helper_1.BNmul(c, sk_, q), q);
    return { c: c, d: d };
};
exports.verifyKeyGenerationProof = function (params, proof, h_, id) {
    var p = params.p, q = params.q, g = params.g;
    var c = proof.c, d = proof.d;
    var b = helper_1.BNdiv(helper_1.BNpow(g, d, p), helper_1.BNpow(h_, c, p), p);
    var c_ = exports.generateChallenge(q, id, h_, b);
    var hashCheck = c.eq(c_);
    var gPowd = helper_1.BNpow(g, d, p);
    var bhPowC = helper_1.BNmul(b, helper_1.BNpow(h_, c, p), p);
    var dCheck = gPowd.eq(bhPowC);
    console.log("do the hashes match?\t", hashCheck);
    console.log('g^d == b * h_^c?\t', dCheck);
    console.log();
    return hashCheck && dCheck;
};
exports.combinePublicKeys = function (params, publicKeyShares) {
    return publicKeyShares.reduce(function (product, share) { return helper_1.BNmul(product, share, params.p); });
};
exports.combinePrivateKeys = function (params, privateKeyShares) {
    return privateKeyShares.reduce(function (sum, share) { return helper_1.BNadd(sum, share, params.q); });
};
exports.decryptShare = function (params, cipher, secretKeyShare) {
    return helper_1.BNpow(cipher.a, secretKeyShare, params.p);
};
exports.combineDecryptedShares = function (params, cipher, decryptedShares) {
    var mh = helper_1.BNdiv(cipher.b, decryptedShares.reduce(function (product, share) { return helper_1.BNmul(product, share, params.p); }), params.p);
    var m = encryption_1.decodeMessage(mh, { p: params.p, g: params.g, q: params.q, h: helper_1.newBN(1) });
    return m;
};
exports.generateChallenge = function (q, uniqueID, h_, b) {
    var c = web3.utils.soliditySha3(uniqueID, h_, b);
    c = web3.utils.toBN(c);
    c = c.mod(q);
    return c;
};
//# sourceMappingURL=keygen.js.map