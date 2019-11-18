"use strict";
var __spreadArrays = (this && this.__spreadArrays) || function () {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isPrime = function (num) {
    for (var i = 2; i <= Math.sqrt(num); i++) {
        if (Math.floor(num / i) == num / i) {
            return false;
        }
    }
    return true;
};
exports.getPrimitiveRoots = function (n) {
    if (!exports.isPrime(n)) {
        return [];
    }
    var g = [];
    for (var i = 1; i < n; i++) {
        var exp = 1;
        var next = i % n;
        while (next !== 1) {
            next = (next * i) % n;
            exp += 1;
        }
        if (exp === n - 1) {
            g.push(i);
        }
    }
    return g;
};
exports.getQofP = function (p) { return (p > 1 ? (p - 1) / 2 : -1); };
exports.isQValid = function (q) { return (q > 1 ? exports.isPrime(q) : false); };
exports.isGValid = function (g, p) {
    return g !== 1 && g !== exports.getQofP(p) && Math.pow(g, exports.getQofP(p)) % p === 1;
};
exports.getPCandidates = function (primes) {
    return primes.reduce(function (previous, current) {
        return exports.isQValid(exports.getQofP(current)) ? __spreadArrays(previous, [current]) : previous;
    }, []);
};
exports.getGCandidates = function (p) {
    return exports.getPrimitiveRoots(exports.getQofP(p)).reduce(function (previous, current) {
        return exports.isGValid(current, p) ? __spreadArrays(previous, [current]) : previous;
    }, []);
};
var crypto = require("crypto");
var BN = require("bn.js");
exports.getSecureRandomValue = function (q) {
    var one = new BN(1, 10);
    var UPPER_BOUND_RANDOM = q.sub(one);
    var RAND_SIZE_BYTES = 1;
    var randomBytes = crypto.randomBytes(RAND_SIZE_BYTES);
    var randomValue = new BN(randomBytes);
    while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(one))) {
        randomBytes = crypto.randomBytes(RAND_SIZE_BYTES);
        randomValue = new BN(randomBytes, 'hex');
    }
    return randomValue;
};
exports.newBN = function (num, base) {
    if (base === void 0) { base = 10; }
    return new BN(num, base);
};
exports.BNadd = function (a, b, modulus) { return a.add(b).mod(modulus); };
exports.BNmul = function (a, b, modulus) { return a.mul(b).mod(modulus); };
exports.BNpow = function (a, b, modulus) { return a.pow(b).mod(modulus); };
exports.BNinvm = function (a, modulus) { return a.invm(modulus); };
exports.BNdiv = function (a, b, modulus) { return exports.BNmul(a, exports.BNinvm(b, modulus), modulus); };
//# sourceMappingURL=helper.js.map