export {};

const { expect } = require("chai");

describe("Simple test suite (with mocha & chai):", function() {
  it("1 === 1 should be true", function() {
    expect(1).to.equal(1);
  });
});
