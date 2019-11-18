"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var BN = require('bn.js');
var hash = require('hash.js');
var random = require('random');
var web3 = require('web3');
var helper_1 = require("./helper");
var printConsole = false;
exports.newBN = function (n) { return new BN(n, 10); };
var add = function (a, b, pk) { return a.add(b).mod(pk.q); };
var sub = function (a, b, pk) { return a.sub(b).mod(pk.q); };
var mul = function (a, b, pk) { return a.mul(b).mod(pk.p); };
var div = function (a, b, pk) { return mul(a, invm(b, pk), pk).mod(pk.p); };
var pow = function (a, b, pk) { return a.pow(b).mod(pk.p); };
var invm = function (a, pk) { return a.invm(pk.p); };
function generateYesProof(cipher, pk, uniqueID) {
    var a = cipher.a, b = cipher.b, r = cipher.r;
    var c0 = helper_1.getSecureRandomValue(pk.q);
    var f0 = helper_1.getSecureRandomValue(pk.q);
    var a0 = div(pow(pk.g, f0, pk), pow(a, c0, pk), pk);
    var b0 = div(pow(pk.h, f0, pk), pow(b, c0, pk), pk);
    var x = helper_1.getSecureRandomValue(pk.q);
    var a1 = pow(pk.g, x, pk);
    var b1 = pow(pk.h, x, pk);
    var c = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1);
    var c1 = add(pk.q, sub(c, c0, pk), pk);
    var c1r = c1.mul(r).mod(pk.q);
    var f1 = add(x, c1r, pk);
    printConsole && console.log('c0\t\t\t', c0.toNumber());
    printConsole && console.log('f0\t\t\t', f0.toNumber());
    printConsole && console.log('a0\t\t\t', a0.toNumber());
    printConsole && console.log('b0\t\t\t', b0.toNumber());
    printConsole && console.log('x\t\t\t', x.toNumber());
    printConsole && console.log('a1\t\t\t', a1.toNumber());
    printConsole && console.log('b1\t\t\t', b1.toNumber());
    printConsole && console.log('c\t\t', c.toNumber());
    printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toNumber());
    printConsole && console.log('f1 = x + c1*r\t\t', f1.toNumber());
    printConsole && console.log();
    return { a0: a0, a1: a1, b0: b0, b1: b1, c0: c0, c1: c1, f0: f0, f1: f1 };
}
exports.generateYesProof = generateYesProof;
function generateNoProof(cipher, pk, uniqueID) {
    var a = cipher.a, b = cipher.b, r = cipher.r;
    var c1 = helper_1.getSecureRandomValue(pk.q);
    var f1 = helper_1.getSecureRandomValue(pk.q);
    var b_ = div(b, pk.g, pk);
    var a1 = div(pow(pk.g, f1, pk), pow(a, c1, pk), pk);
    var b1 = div(pow(pk.h, f1, pk), pow(b_, c1, pk), pk);
    var x = helper_1.getSecureRandomValue(pk.q);
    var a0 = pow(pk.g, x, pk);
    var b0 = pow(pk.h, x, pk);
    var c = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1);
    var c0 = add(pk.q, sub(c, c1, pk), pk);
    var f0 = add(x, c0.mul(r).mod(pk.q), pk);
    printConsole && console.log('c0\t\t\t', c0.toNumber());
    printConsole && console.log('f0\t\t\t', f0.toNumber());
    printConsole && console.log('a0\t\t\t', a0.toNumber());
    printConsole && console.log('b0\t\t\t', b0.toNumber());
    printConsole && console.log('x\t\t\t', x.toNumber());
    printConsole && console.log('a1\t\t\t', a1.toNumber());
    printConsole && console.log('b1\t\t\t', b1.toNumber());
    printConsole && console.log('c\t\t', c.toNumber());
    printConsole && console.log('c1 = (q + (c - c0) % q) % q\t', c1.toNumber());
    printConsole && console.log('f1 = x + c1*r\t\t', f1.toNumber());
    printConsole && console.log();
    return { a0: a0, a1: a1, b0: b0, b1: b1, c0: c0, c1: c1, f0: f0, f1: f1 };
}
exports.generateNoProof = generateNoProof;
function verifyVoteProof(cipher, proof, pk, uniqueID) {
    var a = cipher.a, b = cipher.b;
    var a0 = proof.a0, a1 = proof.a1, b0 = proof.b0, b1 = proof.b1, c0 = proof.c0, c1 = proof.c1, f0 = proof.f0, f1 = proof.f1;
    var l1 = pow(pk.g, f0, pk);
    var r1 = mul(a0, pow(a, c0, pk), pk);
    var v1 = l1.eq(r1);
    var l2 = pow(pk.g, f1, pk);
    var r2 = mul(a1, pow(a, c1, pk), pk);
    var v2 = l2.eq(r2);
    var l3 = pow(pk.h, f0, pk);
    var r3 = mul(b0, pow(b, c0, pk), pk);
    var v3 = l3.eq(r3);
    var l4 = pow(pk.h, f1, pk);
    var r4 = mul(b1, pow(div(b, pk.g, pk), c1, pk), pk);
    var v4 = l4.eq(r4);
    var lc = c1.add(c0).mod(pk.q);
    var rc = generateChallenge(pk.q, uniqueID, a, b, a0, b0, a1, b1);
    var v5 = lc.eq(rc);
    printConsole && console.log('g^f0 == a0*a^c0:\t', v1);
    printConsole && console.log('g^f1 == a1*a^c1\t', v2);
    printConsole && console.log('h^f0 == b0*b^c0\t\t', v3);
    printConsole && console.log('h^f1 == b1*(b/g)^c1\t', v4);
    printConsole && console.log('c == c1 + c0\t\t', v5);
    printConsole && console.log();
    return v1 && v2 && v3 && v4 && v5;
}
exports.verifyVoteProof = verifyVoteProof;
function numbersToString(numbers) {
    var result = '';
    for (var i = 0; i < numbers.length; i++) {
        result += numbers[i].toJSON();
    }
    return result;
}
exports.numbersToString = numbersToString;
function generateChallenge(q, uniqueID, a, b, a0, b0, a1, b1) {
    var c = web3.utils.soliditySha3(uniqueID, a, b, a0, b0, a1, b1);
    c = web3.utils.toBN(c);
    c = c.mod(q);
    return c;
}
exports.generateChallenge = generateChallenge;
//# sourceMappingURL=voteZKP.js.map