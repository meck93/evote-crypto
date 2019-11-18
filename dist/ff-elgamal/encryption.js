"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var helper_1 = require("./helper");
exports.generateKeys = function (_p, _g) {
    var p = helper_1.newBN(_p);
    var q = helper_1.newBN(helper_1.getQofP(_p));
    var g = helper_1.newBN(_g);
    var sk = helper_1.getSecureRandomValue(q);
    var h = helper_1.BNpow(g, sk, p);
    var pk = { p: p, g: g, h: h, q: q };
    return [pk, sk];
};
exports.generateKeysZKP = function (_p, _g) {
    var p = helper_1.newBN(_p);
    var q = helper_1.newBN(helper_1.getQofP(_p));
    var g = helper_1.newBN(_g);
    var sk = helper_1.getSecureRandomValue(q);
    var h = helper_1.BNpow(g, sk, p);
    var pk = { p: p, g: g, h: h, q: q };
    var test1 = helper_1.BNpow(g, q, pk.p);
    if (!test1.eq(helper_1.newBN(1))) {
        throw new Error("g^q mod p != 1 (== " + test1.toNumber() + ". for p: " + _p + ", q: " + q.toNumber() + " and g: " + _g);
    }
    var test2 = helper_1.BNpow(h, q, pk.p);
    if (!test2.eq(helper_1.newBN(1))) {
        throw new Error("h^q mod p != 1 (== " + test2.toNumber() + ". for p: " + _p + ", q: " + q.toNumber() + " and g: " + _g);
    }
    var test3 = h.mod(pk.p);
    if (test3.eq(helper_1.newBN(1))) {
        throw new Error("h mod p == 1. for p: " + _p + ", q: " + q.toNumber() + " and g: " + _g);
    }
    return [pk, sk];
};
exports.encodeMessage = function (m, pk) {
    m = typeof m === 'number' ? helper_1.newBN(m) : m;
    return helper_1.BNpow(pk.g, m, pk.p);
};
exports.decodeMessage = function (mh, pk) {
    mh = typeof mh === 'number' ? helper_1.newBN(mh) : mh;
    var m = helper_1.newBN(0);
    while (!exports.encodeMessage(m, pk).eq(mh)) {
        m = m.add(helper_1.newBN(1));
    }
    return m;
};
exports.encrypt = function (message, pk, log) {
    if (log === void 0) { log = false; }
    var m = typeof message === 'number' ? helper_1.newBN(message) : message;
    var r = helper_1.getSecureRandomValue(pk.q);
    var c1 = helper_1.BNpow(pk.g, r, pk.p);
    var s = helper_1.BNpow(pk.h, r, pk.p);
    var mh = exports.encodeMessage(m, pk);
    var c2 = helper_1.BNmul(s, mh, pk.p);
    log && console.log('enc secret   (r)', r);
    log && console.log('a\t\t', c1);
    log && console.log('h^r\t\t', s);
    log && console.log('g^m\t\t', mh);
    log && console.log('b\t\t', c2);
    log && console.log('------------------------');
    return { a: c1, b: c2, r: r };
};
exports.decrypt1 = function (cipherText, sk, pk, log) {
    if (log === void 0) { log = false; }
    var c1 = cipherText.a, c2 = cipherText.b;
    var s = helper_1.BNpow(c1, sk, pk.p);
    var sInverse = helper_1.BNinvm(s, pk.p);
    var mh = helper_1.BNmul(c2, sInverse, pk.p);
    var m = exports.decodeMessage(mh, pk);
    log && console.log('s\t\t', s);
    log && console.log('s^-1\t\t', sInverse);
    log && console.log('mh\t\t', mh);
    log && console.log('plaintext d1\t', m);
    log && console.log('------------------------');
    return m;
};
exports.decrypt2 = function (cipherText, sk, pk, log) {
    if (log === void 0) { log = false; }
    var c1 = cipherText.a, c2 = cipherText.b;
    var s = helper_1.BNpow(c1, sk, pk.p);
    var sPowPMinus2 = helper_1.BNpow(s, pk.p.sub(helper_1.newBN(2)), pk.p);
    var mh = helper_1.BNmul(c2, sPowPMinus2, pk.p);
    var m = exports.decodeMessage(mh, pk);
    log && console.log('s\t\t', s);
    log && console.log('s^(p-2)\t\t', sPowPMinus2);
    log && console.log('mh\t', mh);
    log && console.log('plaintext d2\t', m);
    log && console.log('------------------------');
    return m;
};
exports.add = function (em1, em2, pk) {
    return {
        a: helper_1.BNmul(em1.a, em2.a, pk.p),
        b: helper_1.BNmul(em1.b, em2.b, pk.p),
    };
};
//# sourceMappingURL=encryption.js.map