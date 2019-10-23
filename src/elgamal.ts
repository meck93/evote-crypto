const BN = require("bn.js");
const random = require("random");
const printConsole = true;

interface PublicKey {
  p: any; // prime
  g: any; // generator
  h: any;
}

interface Cipher {
  c1: any;
  c2: any;
}

const encrypt = (message: any, pk: PublicKey): Cipher => {
  // generate a random value
  const randomValue = new BN(random.int(1, pk.p - 2), 10);
  console.log("enc secret   (r)", randomValue);

  // compute c1: generator^randomValue
  let c1 = pk.g.pow(randomValue).mod(pk.p);
  printConsole && console.log("c1\t\t", c1);

  // compute s: h^randomValue whereby
  // h = publicKey => h = g^privateKeyOfReceiver (h is publically available)
  const s = pk.h.pow(randomValue).mod(pk.p);
  printConsole && console.log("s\t\t", s);

  // compute mh: generator^message
  const mh = pk.g.pow(message).mod(pk.p);
  printConsole && console.log("mh\t\t", mh);

  // compute c2: s*message_homomorphic
  const c2 = s.mul(mh).mod(pk.p);
  printConsole && console.log("c2\t\t", c2);
  printConsole && console.log("------------------------");

  return { c1: c1, c2: c2 };
};

const add = (em1: Cipher, em2: Cipher): Cipher => {
  return {
    c1: em1.c1.mul(em2.c1).mod(p),
    c2: em1.c2.mul(em2.c2).mod(p)
  };
};

const decrypt = (cipherText: Cipher, sk: any, pk: PublicKey): any => {
  let c1 = cipherText.c1;
  let c2 = cipherText.c2;

  // compute s: c1^privateKey
  let s = c1.pow(sk).mod(pk.p);
  printConsole && console.log("s\t\t", s);

  // compute s^-1: the multiplicative inverse of s (probably the most difficult)
  let s_inverse = s.invm(pk.p);
  printConsole && console.log("s^-1\t\t", s_inverse);

  // compute m: c2 * s^-1 | c2 / s
  let m_h = c2.mul(s_inverse).mod(pk.p);
  printConsole && console.log("m_h\t\t", m_h);

  // alternative computation
  // 1. compute p-2
  const pMinusX = pk.p.sub(new BN(2, 10));
  //const pMinusX = p.sub(new BN(2, 10));
  printConsole && console.log("p - 2\t\t", pMinusX);

  // 2. compute pre-result s^(p-x)
  const sPowPMinusX = s.pow(pMinusX).mod(pk.p);
  printConsole && console.log("s^(p-x)\t\t", sPowPMinusX);

  // 3. compute message - msg = c2*s^(p-x)
  let msg_homo = c2.mul(sPowPMinusX).mod(pk.p);
  printConsole && console.log("msg_homo\t", msg_homo);

  // 4.
  let m_ = new BN(1, 10);
  while (
    !pk.g
      .pow(m_)
      .mod(pk.p)
      .eq(m_h)
  ) {
    m_ = m_.add(new BN(1, 10));
  }

  let msg = new BN(1, 10);
  while (
    !pk.g
      .pow(msg)
      .mod(pk.p)
      .eq(msg_homo)
  ) {
    msg = msg.add(new BN(1, 10));
  }

  console.log("plaintexts\t", m_, msg);
  console.log(
    "are plaintexts the same?",
    msg.eq(message),
    msg.eq(m_),
    m_.eq(message)
  );
  printConsole && console.log("------------------------");

  return msg;
};

const p = new BN(7, 10);
const g = new BN(3, 10);
const sk = new BN(random.int(1, p - 2), 10);
const h = g.pow(sk).mod(p);

const pk = { p: p, g: g, h: h };

const message = new BN(random.int(1, pk.p - 1), 10);
for (let i = 0; i < 10; i++) {
  printConsole && console.log(i)
  printConsole && console.log("prime      (p)\t", pk.p);
  printConsole && console.log("generator  (g)\t", pk.g);
  printConsole && console.log("dec secret (x)\t", sk);
  printConsole && console.log("           (h)\t", pk.h);
  console.log("plaintext  (m)\t", message);
  printConsole && console.log("------------------------");
  decrypt(encrypt(message, pk), sk, pk);
  console.log("\n");
}

// plaintext check may be wrong as it is checked against the message from above
const m1 = new BN(2, 10);
const e_m1 = encrypt(m1, pk);
//const d_m1 = decrypt(e_m1, sk, p, gen);

const m2 = new BN(3, 10);
const e_m2 = encrypt(m2, pk);
//const d_m2 = decrypt(e_m2, sk, p, gen);

const d_sum = decrypt(add(e_m1, e_m2), sk, pk);
console.log(d_sum);
