import { AztecAddress, createPXEClient } from "@aztec/aztec.js";
import { getDeployedTestAccountsWallets } from "@aztec/accounts/testing";

import fs from "fs";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { encodePacked, padTo } from "./lib/encoding";
import { normalizeV } from "./lib/crypto";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";
import { AttVerifierContract } from "./bindings/AttVerifier.js";
const pxe = await createPXEClient("http://localhost:8080");

const alice = (await getDeployedTestAccountsWallets(pxe))[0];
const bob = (await getDeployedTestAccountsWallets(pxe))[1];

// deploy business program
const businessProgram = await BusinessProgramContract.deploy(alice).send({ from: alice.getAddress() })
  .deployed();;
// test calling verify()
// let reuslt = await businessProgram.methods.verify([1, 2, 3]).send({ from: alice.getAddress() })
//   .wait();
// console.log(reuslt);

// deploy attVerifierContract
const attVerifierContract = await AttVerifierContract.deploy(alice).send({ from: alice.getAddress() })
  .deployed();

// --- prepare inputs for verify_attestation ---
const MAX_URL_LEN = 1024;
const MAX_ALLOWED_URLS = 10;

// load attestation testdata
const obj = JSON.parse(fs.readFileSync("testdata/attestation_data.json", "utf-8"));

// pack data
const packedArr = encodePacked(obj.public_data);

// signature
// signature is 65 bytes (r||s||v)
const sigHex = obj.public_data.signatures[0].slice(2);
const sigBytes = Buffer.from(sigHex, "hex");

// extract r, s, v
const r = BigInt("0x" + sigBytes.slice(0, 32).toString("hex"));
const s = BigInt("0x" + sigBytes.slice(32, 64).toString("hex"));
let v = sigBytes[64];
if (v === 27 || v === 28) v -= 27;
const sig = new secp256k1.Signature(r, s, v);

// prepare 64-byte compact signature for Noir circuit input
const signature = Array.from(sig.toCompactRawBytes());

// hash of packed data
const msgHash = keccak_256(new Uint8Array(packedArr));
const hash = Array.from(msgHash);

// recover pubkey
const pubkey = sig.recoverPublicKey(msgHash);

// get raw uncompressed 65 bytes (04 || x || y)
const pubBytes = pubkey.toRawBytes(false);
const public_key_x = Array.from(pubBytes.slice(1, 33));
const public_key_y = Array.from(pubBytes.slice(33, 65));

// request_url
const urlStr: string = obj.public_data.request.url;
const urlBytes = Array.from(new TextEncoder().encode(urlStr));

// Get ciphertext data
const dataObj = JSON.parse(obj.public_data.data);
const chrc = JSON.parse(dataObj.CompleteHttpResponseCiphertext);

let allCiphertexts: number[][] = [];
let allNonces: number[][] = [];
let allJsonBlocks: [number, number][] = []; // NEW

for (const packet of chrc.packets) {
  for (const record of packet.records) {
    const ctBytes = Array.from(Buffer.from(record.ciphertext, "hex"));
    const nonceBytes = Array.from(Buffer.from(record.nonce, "hex"));
    allCiphertexts.push(ctBytes);
    allNonces.push(nonceBytes);

    // grab json_block_positions (0 or 1 range in current data)
    if (record.json_block_positions && record.json_block_positions.length > 0) {
      const [start, end] = record.json_block_positions[0];
      allJsonBlocks.push([start, end]);
    } else {
      allJsonBlocks.push([0, 0]);
    }
  }
}

function padArray(arr: number[], target: number): number[] {
  if (arr.length > target) {
    throw new Error(`Array too long: ${arr.length} > ${target}`);
  }
  return arr.concat(new Array(target - arr.length).fill(0));
}

const MAX_CT = 4;
const CT_SLOT_SIZE = 1536;
const NONCE_SIZE = 12;

let ciphertextsFixed: number[][] = [];
let ciphertextLengths: number[] = [];
let noncesFixed: number[][] = [];
let jsonBlocksFixed: [number, number][] = []; // NEW

for (let i = 0; i < MAX_CT; i++) {
  if (i < allCiphertexts.length) {
    ciphertextsFixed.push(padArray(allCiphertexts[i], CT_SLOT_SIZE));
    ciphertextLengths.push(allCiphertexts[i].length);
    noncesFixed.push(padArray(allNonces[i], NONCE_SIZE));
    jsonBlocksFixed.push(allJsonBlocks[i] || [0, 0]);
  } else {
    ciphertextsFixed.push(new Array(CT_SLOT_SIZE).fill(0));
    ciphertextLengths.push(0);
    noncesFixed.push(new Array(NONCE_SIZE).fill(0));
    jsonBlocksFixed.push([0, 0]);
  }
}

const number_of_ciphertexts = allCiphertexts.length;

// aes_key from test data (16 bytes hex string assumed)
const aes_key = padArray(Array.from(Buffer.from(obj.private_data.aes_key, "hex")), 16);

console.log("nr ciphertexts: ", ciphertextsFixed.length);
console.log("nr nonces: ", noncesFixed.length);
console.log("nr json blocks: ", jsonBlocksFixed.length);
let result = await attVerifierContract.methods.verify_attestation(
  public_key_x,
  public_key_y,
  hash,
  signature,
  urlBytes,
  ciphertextsFixed,
  number_of_ciphertexts,
  jsonBlocksFixed,
  noncesFixed,
  aes_key,
  businessProgram.address
).send({ from: alice.getAddress() }).wait();
console.log(result);
