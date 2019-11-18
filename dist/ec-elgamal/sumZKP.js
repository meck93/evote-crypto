"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = require("../index");
var BN = require("bn.js");
var EC = require('elliptic').ec;
var secp256k1 = new EC('secp256k1');
var log = true;
var BNadd = function (a, b, params) { return a.add(b).mod(params.n); };
var BNsub = function (a, b, params) { return a.sub(b).mod(params.n); };
var BNmul = function (a, b, params) { return a.mul(b).mod(params.n); };
var ECpow = function (a, b) { return a.mul(b); };
var ECmul = function (a, b) { return a.add(b); };
var ECdiv = function (a, b) { return a.add(b.neg()); };
exports.generateSumProof = function (encryptedVote, params, sk, id) {
    var a = encryptedVote.a, b = encryptedVote.b;
    var p = params.p, h = params.h, g = params.g, n = params.n;
    var x = index_1.ECelGamal.Helper.getSecureRandomValue();
    var a1 = ECpow(a, x);
    var b1 = ECpow(g, x);
    var c = generateChallenge(n, id, a, b, a1, b1);
    var cr = BNmul(c, sk, params);
    var f = BNadd(x, cr, params);
    var d = ECpow(a, sk);
    log && console.log('a1 is on the curve?\t', secp256k1.curve.validate(a1));
    log && console.log('b1 is on the curve?\t', secp256k1.curve.validate(b1));
    log && console.log('d is on the curve?\t', secp256k1.curve.validate(d));
    log && console.log('x\t\t\t', x);
    log && console.log('a1\t\t\t', a1);
    log && console.log('b1\t\t\t', b1);
    log && console.log('c\t\t\t', c);
    log && console.log('f = x + c*r\t\t', f);
    log && console.log();
    return { a1: a1, b1: b1, f: f, d: d };
};
exports.verifySumProof = function (encryptedSum, proof, params, pk, id) {
    var a = encryptedSum.a, b = encryptedSum.b;
    var p = params.p, h = params.h, g = params.g, n = params.n;
    var a1 = proof.a1, b1 = proof.b1, f = proof.f, d = proof.d;
    var c = generateChallenge(n, id, a, b, a1, b1);
    var l1 = ECpow(a, f);
    var r1 = ECmul(a1, ECpow(d, c));
    var v1 = l1.eq(r1);
    var l2 = ECpow(g, f);
    var r2 = ECmul(b1, ECpow(h, c));
    var v2 = l2.eq(r2);
    log && console.log('a^f == a1*d^c:\t\t', v1);
    log && console.log('g^f == b1*h^c\t\t', v2);
    log && console.log();
    return v1 && v2;
};
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
function generateChallenge(n, id, a, b, a1, b1) {
    var pointsAsString = convertAllECPointsToString([a, b, a1, b1]);
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
//# sourceMappingURL=sumZKP.js.map