"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var helper_1 = require("./helper");
var EC = require('elliptic').ec;
var secp256k1 = new EC('secp256k1');
var shouldLog = false;
exports.encrypt = function (message, pubK) {
    var r = helper_1.getSecureRandomValue();
    var c1 = secp256k1.g.mul(r);
    var s = pubK.mul(r);
    var c2 = s.add(message);
    shouldLog && console.log('Is c1 on the curve?', secp256k1.curve.validate(c1));
    shouldLog && console.log('Is point s on the curve?', secp256k1.curve.validate(s));
    shouldLog && console.log('is c2 on curve?', secp256k1.curve.validate(c2));
    return { a: c1, b: c2, r: r };
};
exports.decrypt = function (cipherText, privK) {
    var c1 = cipherText.a, c2 = cipherText.b;
    var s = c1.mul(privK);
    var sInverse = s.neg();
    var m = c2.add(sInverse);
    shouldLog && console.log('is s on the curve?', secp256k1.curve.validate(s));
    shouldLog && console.log('is s^-1 on the curve?', secp256k1.curve.validate(sInverse));
    shouldLog && console.log('is m on curve?', secp256k1.curve.validate(m));
    return m;
};
exports.homomorphicAdd = function (cipher0, cipher1) {
    return {
        a: cipher0.a.add(cipher1.a),
        b: cipher0.b.add(cipher1.b),
    };
};
//# sourceMappingURL=encryption.js.map