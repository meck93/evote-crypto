const BN = require("bn.js");
const hash = require("hash.js");

const random = require("random");

function generateWithReductionContext() {
  let p_red = BN.red(new BN(7, 10));
  const t = new BN(3, 10);

  console.log("p\t", p_red);

  const t_red = t.toRed(p_red);
  console.log("t\t", t_red);

  const t2 = t_red.redPow(t);
  console.log(t2);
}

function generate() {
  let p = new BN(7, 10);
  const g = new BN(3, 10);

  const x = new BN(random.int(0, 6), 10);
  const gPowX = g.pow(x).mod(p);

  const x_ = new BN(random.int(0, 6), 10);
  const gPowX_ = g.pow(x_).mod(p);

  const gPowXgPowX_ = gPowX.mul(gPowX_).mod(p);

  const y = new BN(random.int(0, 6), 10);
  const gPowY = g.pow(y).mod(p);

  const y_ = new BN(random.int(0, 6), 10);
  const gPowY_ = g.pow(y_).mod(p);

  const gPowYgPowY_ = gPowY.mul(gPowY_).mod(p);

  const z = new BN(random.int(0, 6), 10);
  const gPowZ = g.pow(z).mod(p);

  const w = new BN(random.int(0, 6), 10);
  const g_ = g.pow(w).mod(p);

  const pk = [p, g, g_, gPowXgPowX_, gPowYgPowY_, gPowZ];
  const sk = [x, x_, y, y_, z];

  return [pk, sk];
}

function encryptCramerShoup(pk, m) {
  const r = new BN(random.int(0, 6), 10);

  const p = pk[0];
  const g = pk[1];
  const g_ = pk[2];
  const u = pk[3];
  const v = pk[4];
  const z = pk[5];

  const a = g.pow(r).mod(p);
  const b = g_.pow(r).mod(p);
  let c = z.pow(r).mod(p);
  c = c.mul(m).mod(p);

  const uPowR = u.pow(r).mod(p);
  const vPowR = v.pow(r).mod(p);
  const uPowRvPowR = uPowR.mul(vPowR).mod(p);

  let hash = hashMe(a, b, c);

  // TODO: FIGURE OUT WHY THIS DOESN'T WORK!!!
  hash = new BN(hash, "hex");

  const hash_ = uPowRvPowR.pow(hash).mod(p);
  return [a, b, c, hash_];
}

function hashMe(a, b, c) {
  // TODO: Fix this with real hash function
  const input = [a, b, c];
  console.log(input);
  const buffer = new BN(input);

  //   console.log(buffer, buffer.toBuffer("be", 10));
  const result = hash
    .sha256()
    .update(buffer)
    .digest("hex");
  console.log(result);
  return result;
}

function encrypt(message, pk, randomValue) {
  // INPUTS: message is a ECC point, publicKey is a

  console.log("public key\t", pk);

  // ADDITIONALLY, the generator g of the curve is required
  console.log("generator\t", gen);

  // compute c1: generator^randomValue
  let c1 = gen.pow(randomValue).mod(p);
  console.log("c1\t", c1);

  // compute s: h^randomValue whereby h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  // compute c2: s*message
  const s = pk.pow(randomValue).mod(p);
  const c2 = s.mul(message).mod(p);
  console.log("s\t", s);
  console.log("c2\t", c2);

  return [c1, c2];
}

function decrypt(sk, cipherText) {
  let c1 = cipherText[0];
  let c2 = cipherText[1];

  // compute s: c1^privateKey
  let s = c1.pow(sk).mod(p);
  console.log("s\t", s);

  // alternative computation
  // 1. compute p-x
  const pMinusX = p.sub(sk);
  console.log("p - x\t", pMinusX);

  // 2. compute pre-result s^(p-x)
  const sPowPMinusX = s.pow(pMinusX).mod(p);
  console.log("s^(p-x)\t", sPowPMinusX);

  // 3. compute message - msg = c2*s^(p-x)
  let msg = c2.mul(sPowPMinusX).mod(p);
  console.log("plaintext\t", msg);
  console.log("are plaintexts the same?", msg.eq(message));

  return msg;
}

const sk = new BN(2, 10);
const gen = new BN(3, 10);
const p = new BN(7, 10);
const pk = gen.pow(sk).mod(p);
console.log("public key\t", pk);

const randomValue = new BN(random.int(0, p - 1), 10);
console.log("random value\t", randomValue);

const message = new BN(5, 10);
console.log("plaintext\t", message);

decrypt(sk, encrypt(message, pk, randomValue));
const result = generate();
console.log(result);

encryptCramerShoup(result[0], new BN(1, 10));
console.log(hashMe(1, 2, 3));
