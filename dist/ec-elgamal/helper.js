"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var BN = require("bn.js");
var EC = require('elliptic').ec;
var secp256k1 = new EC('secp256k1');
var RAND_SIZE_BYTES = 32;
var UPPER_BOUND_RANDOM = secp256k1.curve.n.sub(new BN(1, 10));
exports.getSecureRandomValue = function () {
    var randomBytes = crypto.randomBytes(RAND_SIZE_BYTES);
    var randomValue = new BN(randomBytes, 'hex');
    while (!(randomValue.lte(UPPER_BOUND_RANDOM) && randomValue.gte(new BN(1)))) {
        randomBytes = crypto.randomBytes(RAND_SIZE_BYTES);
        randomValue = new BN(randomBytes, 'hex');
    }
    return randomValue;
};
//# sourceMappingURL=helper.js.map