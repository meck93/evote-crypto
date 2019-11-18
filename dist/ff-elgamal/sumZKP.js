"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var helper_1 = require("./helper");
var BN = require("bn.js");
var web3 = require('web3');
var printConsole = false;
exports.newBN = function (n) { return new BN(n, 10); };
var add = function (a, b, pk) { return a.add(b).mod(pk.q); };
var mul = function (a, b, pk) { return a.mul(b).mod(pk.p); };
var pow = function (a, b, pk) { return a.pow(b).mod(pk.p); };
function generateSumProof(cipher, pk, sk, uniqueID) {
    var a = cipher.a, b = cipher.b;
    var x = helper_1.getSecureRandomValue(pk.q);
    var a1 = pow(a, x, pk);
    var b1 = pow(pk.g, x, pk);
    var c = generateChallenge(pk.q, uniqueID, a, b, a1, b1);
    var cr = c.mul(sk).mod(pk.q);
    var f = add(x, cr, pk);
    var d = pow(a, sk, pk);
    printConsole && console.log('x\t\t\t', x.toNumber());
    printConsole && console.log('a1\t\t\t', a1.toNumber());
    printConsole && console.log('b1\t\t\t', b1.toNumber());
    printConsole && console.log('c\t\t\t', c.toNumber());
    printConsole && console.log('f = x + c*r\t\t', f.toNumber());
    printConsole && console.log();
    return { a1: a1, b1: b1, f: f, d: d };
}
exports.generateSumProof = generateSumProof;
function verifySumProof(cipher, proof, pk, uniqueID) {
    var a = cipher.a, b = cipher.b;
    var a1 = proof.a1, b1 = proof.b1, f = proof.f, d = proof.d;
    var c = generateChallenge(pk.q, uniqueID, a, b, a1, b1);
    var l1 = pow(a, f, pk);
    var r1 = mul(a1, pow(d, c, pk), pk);
    var v1 = l1.eq(r1);
    var l2 = pow(pk.g, f, pk);
    var r2 = mul(b1, pow(pk.h, c, pk), pk);
    var v2 = l2.eq(r2);
    printConsole && console.log('a^f == a1*d^c:\t\t', v1, l1.toNumber(), r1.toNumber());
    printConsole && console.log('g^f == b1*h^c\t\t', v2, l2.toNumber(), r2.toNumber());
    printConsole && console.log();
    return v1 && v2;
}
exports.verifySumProof = verifySumProof;
function numbersToString(numbers) {
    var result = '';
    for (var i = 0; i < numbers.length; i++) {
        result += numbers[i].toJSON();
    }
    return result;
}
exports.numbersToString = numbersToString;
function generateChallenge(q, uniqueID, a, b, a1, b1) {
    var c = web3.utils.soliditySha3(uniqueID, a, b, a1, b1);
    c = web3.utils.toBN(c);
    c = c.mod(q);
    return c;
}
exports.generateChallenge = generateChallenge;
//# sourceMappingURL=sumZKP.js.map