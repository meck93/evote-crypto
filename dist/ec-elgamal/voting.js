"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var encryption_1 = require("./encryption");
var _1 = require("./");
var _2 = require("./");
var EC = require('elliptic').ec;
var secp256k1 = new EC('secp256k1');
var startingPoint = secp256k1.curve.g;
var infinityPoint = startingPoint.add(startingPoint.neg());
exports.generateYesVote = function (pk) {
    var publicKey;
    if (typeof pk === 'string' || pk instanceof String) {
        publicKey = secp256k1.keyFromPublic(pk, 'hex').pub;
    }
    else {
        publicKey = pk;
    }
    return encryption_1.encrypt(startingPoint, publicKey);
};
exports.generateNoVote = function (pk) {
    var publicKey;
    if (typeof pk === 'string' || pk instanceof String) {
        publicKey = secp256k1.keyFromPublic(pk, 'hex').pub;
    }
    else {
        publicKey = pk;
    }
    return encryption_1.encrypt(startingPoint.neg(), publicKey);
};
exports.addVotes = function (votes, pk) {
    var publicKey;
    if (typeof pk === 'string' || pk instanceof String) {
        publicKey = secp256k1.keyFromPublic(pk, 'hex').pub;
    }
    else {
        publicKey = pk;
    }
    return votes.reduce(function (previous, current) { return encryption_1.homomorphicAdd(previous, current); }, encryption_1.encrypt(infinityPoint, publicKey));
};
exports.findPoint = function (point) {
    var pointPositive = startingPoint;
    var pointNegative = startingPoint.neg();
    var counter = 1;
    while (!(point.eq(pointPositive) || point.eq(pointNegative))) {
        pointPositive = pointPositive.add(startingPoint);
        pointNegative = pointNegative.add(startingPoint.neg());
        counter += 1;
    }
    return point.eq(pointNegative) ? -counter : counter;
};
exports.tallyVotes = function (pk, sk, votes) {
    var publicKey = secp256k1.keyFromPublic(pk, 'hex').pub;
    var sum = encryption_1.decrypt(exports.addVotes(votes, publicKey), sk);
    return sum.eq(infinityPoint) ? 0 : exports.findPoint(sum);
};
exports.checkDecrypedSum = function (decryptedSum) {
    return decryptedSum.eq(infinityPoint) ? 0 : exports.findPoint(decryptedSum);
};
exports.getSummary = function (total, tallyResult) {
    var yes = 0;
    var no = 0;
    if (tallyResult === 0) {
        yes = total / 2;
        no = total / 2;
    }
    else if (tallyResult < 0) {
        var diff = (total + tallyResult) / 2;
        no = -1 * tallyResult + diff;
        yes = total - no;
    }
    else if (tallyResult > 0) {
        var diff = (total - tallyResult) / 2;
        yes = tallyResult + diff;
        no = total - yes;
    }
    return { total: total, yes: yes, no: no };
};
function generateYesProof(encryptedVote, params, id) {
    var _params = createParams(params);
    return _1.VoteZKP.generateYesProof(encryptedVote, _params, id);
}
exports.generateYesProof = generateYesProof;
exports.generateNoProof = function (encryptedVote, params, id) {
    var _params = createParams(params);
    return _1.VoteZKP.generateNoProof(encryptedVote, _params, id);
};
exports.generateSumProof = function (encryptedVote, params, sk, id) {
    var _params = createParams(params);
    return _2.SumZKP.generateSumProof(encryptedVote, _params, sk, id);
};
exports.verifyZKP = function (encryptedVote, proof, params, id) {
    var _params = createParams(params);
    return _1.VoteZKP.verifyZKP(encryptedVote, proof, _params, id);
};
exports.verifySumProof = function (encryptedSum, proof, params, pk, id) {
    var _params = createParams(params);
    var publicKey = secp256k1.keyFromPublic(pk, 'hex').pub;
    return _2.SumZKP.verifySumProof(encryptedSum, proof, _params, publicKey, id);
};
var createParams = function (params) {
    return {
        p: params.p,
        n: params.n,
        g: secp256k1.curve.pointFromJSON(params.g),
        h: secp256k1.keyFromPublic(params.h, 'hex').pub,
    };
};
//# sourceMappingURL=voting.js.map