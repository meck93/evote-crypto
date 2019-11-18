"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var encryption_1 = require("./encryption");
exports.generateYesVote = function (pk) {
    return encryption_1.encrypt(1, pk);
};
exports.generateNoVote = function (pk) {
    return encryption_1.encrypt(0, pk);
};
exports.addVotes = function (votes, pk) {
    return votes.reduce(function (previous, current) { return encryption_1.add(previous, current, pk); }, exports.generateNoVote(pk));
};
exports.tallyVotes = function (pk, sk, votes) {
    return encryption_1.decrypt1(exports.addVotes(votes, pk), sk, pk).toNumber();
};
exports.getSummary = function (total, tallyResult) {
    var yes = tallyResult - 0;
    var no = total - yes;
    return { total: total, yes: yes, no: no };
};
//# sourceMappingURL=voting.js.map