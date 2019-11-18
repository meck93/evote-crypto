"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var EC = require('elliptic').ec;
var secp256k1 = new EC('secp256k1');
var index_1 = require("../index");
var BN = require("bn.js");
var printConsole = false;
var BNadd = function (a, b, params) { return a.add(b).mod(params.n); };
var BNsub = function (a, b, params) { return a.sub(b).mod(params.n); };
var BNmul = function (a, b, params) { return a.mul(b).mod(params.n); };
var ECpow = function (a, b) { return a.mul(b); };
var ECmul = function (a, b) { return a.add(b); };
var ECdiv = function (a, b) { return a.add(b.neg()); };
function generateYesProof(encryptedVote, params, id) {
    var a = encryptedVote.a, b = encryptedVote.b, r = encryptedVote.r;
    var h = params.h, g = params.g, n = params.n;
    if (r === undefined || r === null) {
        throw new Error('value r is undefined');
    }
    var c0 = index_1.ECelGamal.Helper.getSecureRandomValue();
    var f0 = index_1.ECelGamal.Helper.getSecureRandomValue();
    var a0 = ECdiv(ECpow(g, f0), ECpow(a, c0));
    var b0 = ECdiv(ECpow(h, f0), ECpow(b, c0));
    var x = index_1.ECelGamal.Helper.getSecureRandomValue();
    var a1 = ECpow(g, x);
    var b1 = ECpow(h, x);
    var c = generateChallenge(n, id, a, b, a0, b0, a1, b1);
    var c1 = BNadd(n, BNsub(c, c0, params), params);
    var c1r = BNmul(c1, r, params);
    var f1 = BNadd(x, c1r, params);
    printConsole && console.log('a0 is on the curve?\t', secp256k1.curve.validate(a0));
    printConsole && console.log('b0 is on the curve?\t', secp256k1.curve.validate(b0));
    printConsole && console.log('a1 is on the curve?\t', secp256k1.curve.validate(a1));
    printConsole && console.log('b1 is on the curve?\t', secp256k1.curve.validate(b1));
    printConsole && console.log('c0\t\t\t\t', c0.toString('hex'));
    printConsole && console.log('f0\t\t\t\t', f0.toString('hex'));
    printConsole && console.log('x\t\t\t\t', x.toString('hex'));
    printConsole && console.log('c\t\t\t\t', c.toString('hex'));
    printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toString('hex'));
    printConsole && console.log('f1 = x + c1*r\t\t\t', f1.toString('hex'));
    printConsole && console.log();
    return { a0: a0, a1: a1, b0: b0, b1: b1, c0: c0, c1: c1, f0: f0, f1: f1 };
}
exports.generateYesProof = generateYesProof;
function generateNoProof(encryptedVote, params, id) {
    var a = encryptedVote.a, b = encryptedVote.b, r = encryptedVote.r;
    var h = params.h, g = params.g, n = params.n;
    if (r === undefined || r === null) {
        throw new Error('value r is undefined');
    }
    var c1 = index_1.ECelGamal.Helper.getSecureRandomValue();
    var f1 = index_1.ECelGamal.Helper.getSecureRandomValue();
    var b_ = ECdiv(b, g);
    var a1 = ECdiv(ECpow(g, f1), ECpow(a, c1));
    var b1 = ECdiv(ECpow(h, f1), ECpow(b_, c1));
    var x = index_1.ECelGamal.Helper.getSecureRandomValue();
    var a0 = ECpow(g, x);
    var b0 = ECpow(h, x);
    var c = generateChallenge(n, id, a, b, a0, b0, a1, b1);
    var c0 = BNadd(n, BNsub(c, c1, params), params);
    var c0r = BNmul(c0, r, params);
    var f0 = BNadd(x, c0r, params);
    printConsole && console.log('a1 is on the curve?\t', secp256k1.curve.validate(a1));
    printConsole && console.log('b1 is on the curve?\t', secp256k1.curve.validate(b1));
    printConsole && console.log('a0 is on the curve?\t', secp256k1.curve.validate(a0));
    printConsole && console.log('b0 is on the curve?\t', secp256k1.curve.validate(b0));
    printConsole && console.log('c1\t\t\t\t', c1.toString('hex'));
    printConsole && console.log('f1\t\t\t\t', f1.toString('hex'));
    printConsole && console.log('x\t\t\t\t', x.toString('hex'));
    printConsole && console.log('c\t\t\t\t', c.toString('hex'));
    printConsole && console.log('c0 = (q + (c - c1) % q) % q\t', c0.toString('hex'));
    printConsole && console.log('f0 = x + c0*r\t\t\t', f0.toString('hex'));
    printConsole && console.log();
    return { a0: a0, a1: a1, b0: b0, b1: b1, c0: c0, c1: c1, f0: f0, f1: f1 };
}
exports.generateNoProof = generateNoProof;
function verifyZKP(encryptedVote, proof, params, id) {
    var a0 = proof.a0, a1 = proof.a1, b0 = proof.b0, b1 = proof.b1, c0 = proof.c0, c1 = proof.c1, f0 = proof.f0, f1 = proof.f1;
    var h = params.h, g = params.g, n = params.n;
    var a = encryptedVote.a, b = encryptedVote.b;
    var l1 = ECpow(g, f0);
    var r1 = ECmul(a0, ECpow(a, c0));
    var v1 = l1.eq(r1);
    var l2 = ECpow(g, f1);
    var r2 = ECmul(a1, ECpow(a, c1));
    var v2 = l2.eq(r2);
    var l3 = ECpow(h, f0);
    var r3 = ECmul(b0, ECpow(b, c0));
    console.log('r3 == l3?\t\t', l3.eq(r3), '\n');
    var v3 = l3.eq(r3);
    var l4 = ECpow(h, f1);
    var r4 = ECmul(b1, ECpow(ECdiv(b, g), c1));
    var v4 = l4.eq(r4);
    var lc = BNadd(c0, c1, params);
    var rc = generateChallenge(n, id, a, b, a0, b0, a1, b1);
    var v5 = lc.eq(rc);
    printConsole && console.log('g^f0 == a0*a^c0:\t', v1);
    printConsole && console.log('g^f1 == a1*a^c1\t\t', v2);
    printConsole && console.log('h^f0 == b0*b^c0\t\t', v3);
    printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4);
    printConsole && console.log('c == c1 + c0\t\t', v5);
    printConsole && console.log();
    return v1 && v2 && v3 && v4 && v5;
}
exports.verifyZKP = verifyZKP;
function generateChallenge(n, id, c1, c2, a1, a2, b1, b2) {
    var pointsAsString = convertAllECPointsToString([c1, c2, a1, a2, b1, b2]);
    var input = id + pointsAsString;
    var c = secp256k1
        .hash()
        .update(input)
        .digest('hex');
    c = new BN(c, 'hex');
    c = c.mod(n);
    return c;
}
exports.generateChallenge = generateChallenge;
function convertECPointToString(point) {
    var pointAsJSON = point.toJSON();
    var Px = pointAsJSON[0].toString('hex');
    var Py = pointAsJSON[1].toString('hex');
    return Px + Py;
}
exports.convertECPointToString = convertECPointToString;
function convertAllECPointsToString(points) {
    var asString = '';
    for (var _i = 0, points_1 = points; _i < points_1.length; _i++) {
        var point = points_1[_i];
        asString += convertECPointToString(point);
    }
    return asString;
}
exports.convertAllECPointsToString = convertAllECPointsToString;
//# sourceMappingURL=voteZKP.js.map