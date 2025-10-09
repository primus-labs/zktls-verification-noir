import { AztecAddress, createPXEClient } from "@aztec/aztec.js";
import { getDeployedTestAccountsWallets } from "@aztec/accounts/testing";
import { BusinessProgramContract } from "./bindings/BusinessProgram.ts"

import fs from "fs";
import { keccak_256 } from "@noble/hashes/sha3";
import * as secp from "@noble/secp256k1";
import { encodePacked, padTo } from "./lib/encoding";
import { normalizeV, pubkeyToEthAddress } from "./lib/crypto";
import { AttVerifierContract } from "./bindings/AttVerifier.ts";

const pxe = await createPXEClient("http://localhost:8080");

const alice = (await getDeployedTestAccountsWallets(pxe))[0];
const bob = (await getDeployedTestAccountsWallets(pxe))[1];

// deploy business program
const businessProgram = await BusinessProgramContract.deploy(alice).send({ from: alice.getAddress() })
  .deployed();;
// test calling verify()
let reuslt = await businessProgram.methods.verify([1, 2, 3]).send({ from: alice.getAddress() })
  .wait();
console.log(reuslt);

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
let sigHex = obj.public_data.signatures[0].slice(2);
const sigBytes = Buffer.from(sigHex, "hex");
const v = normalizeV(sigBytes[64]);
// move the recover_id to the first byte
const signature = Array.from(sigBytes);
signature.pop()
signature.unshift(v);

// hash of packed data
const msgHash = keccak_256(new Uint8Array(packedArr));
const hash = Array.from(msgHash);

// recover pubkey
const pubkey = secp.recoverPublicKey(Uint8Array.from(signature), msgHash, { prehash: false });
if (!pubkey) throw new Error("Failed to recover public key");
const pubBytes = pubkey.slice(1);
const public_key_x = Array.from(pubBytes.slice(0, 32));
const public_key_y = Array.from(pubBytes.slice(32, 64));

// request_url
const urlStr: string = obj.public_data.request.url;
const urlBytes = Array.from(new TextEncoder().encode(urlStr));

// Get ciphertext data
const dataObj = JSON.parse(obj.public_data.data);
const chrc = JSON.parse(dataObj.CompleteHttpResponseCiphertext);

let allCiphertexts: number[][] = [];
let allNonces: number[][] = [];
let allBlockPositions: [number, number][][] = [];
for (const packet of chrc.packets) {
  for (const record of packet.records) {
    const ctBytes = Array.from(Buffer.from(record.ciphertext, "hex"));
    const nonceBytes = Array.from(Buffer.from(record.nonce, "hex"));

    allCiphertexts.push(ctBytes);
    allNonces.push(nonceBytes);
    allBlockPositions.push(record.json_block_positions);
  }
}
// Flatten ciphertexts and collect lengths
let flatCiphertexts: number[] = [];
let ciphertextLengths: number[] = [];

for (const ct of allCiphertexts) {
  flatCiphertexts.push(...ct);
  ciphertextLengths.push(ct.length);
}

console.log("Flat ciphertext total length:", flatCiphertexts.length);
console.log("Ciphertext lengths array:", ciphertextLengths);

// ciphertexts: [u8; 7000]
const ciphertextsFixed = padTo(flatCiphertexts, 7000); // pad to 7000 bytes

// call verify_attestation
let result = await attVerifierContract.methods.verify_attestation(
  public_key_x,
  public_key_y,
  hash,
  signature,
  urlBytes,
  ciphertextsFixed,
  ciphertextLengths,
  businessProgram.address,
).send({ from: alice.getAddress() }).wait();
console.log(result);
