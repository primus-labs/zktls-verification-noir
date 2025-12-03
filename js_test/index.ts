import fs from "fs";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { encodePacked, padTo } from "./lib/encoding";
import { normalizeV } from "./lib/crypto";
import { AttVerifierContract, SuccessEvent } from "./bindings/AttVerifier.js";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { TestWallet } from "@aztec/test-wallet/server";
import { createStore } from "@aztec/kv-store/lmdb";
import { createPXE, getPXEConfig, PXE } from "@aztec/pxe/server";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";
import { performance } from "perf_hooks";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { rm } from "node:fs/promises";
import { Barretenberg, Fr } from "@aztec/bb.js";
import { url } from "inspector";

const MAX_RESPONSE_NUM = 2;
const AllOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/attestation_data_grumpkin.json";

// Safe max nr of bits that can be encoded in a chunk because Field modulus has 254 bits
const GRUMPKIN_BATCH_SIZE = 253;

const node = createAztecNodeClient("http://localhost:8080");

const config = getPXEConfig();
await rm("pxe", { recursive: true, force: true });
config.dataDirectory = "pxe";
config.proverEnabled = true;
const wallet = await TestWallet.create(node, config);
const [aliceAccount, bobAccount] = await getInitialTestAccountsData();
let alice = await wallet.createSchnorrAccount(aliceAccount.secret, aliceAccount.salt);
let bob = await wallet.createSchnorrAccount(bobAccount.secret, bobAccount.salt);

// deploy attVerifierContract
const attVerifierContract = await AttVerifierContract.deploy(wallet).send({ from: aliceAccount.address })
  .deployed();
console.log("deployed attverifier");

// load attestation testdata
const obj = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));

// pack data
const packedArr = encodePacked(obj.public_data[0].attestation);

// signature is 65 bytes (r||s||v)
const sigHex = obj.public_data[0].signature.slice(2);
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
// check if request num > MAX_RESPONSE_NUM
if (obj.public_data[0].attestation.request.length > MAX_RESPONSE_NUM) {
  throw new Error(`request length (${obj.public_data[0].attestation.request.length}) > MAX_RESPONSE_NUM (${MAX_RESPONSE_NUM})`)
}
const requestUrls: (bigint | number)[][] = [];
for (const req of obj.public_data[0].attestation.request) {
  const urlBytes = Array.from(new TextEncoder().encode(req.url));
  requestUrls.push(urlBytes)
}

// repeat the last element till MAX_RESPONSE_NUM 
const diff = MAX_RESPONSE_NUM - requestUrls.length;
for (let i = 0; i < diff; i++) {
  requestUrls.push(requestUrls.at(-1) as number[]);
}

// allowed urls
const allowedUrls: (bigint | number)[][] = [];
for (const url of AllOWED_URL) {
  const url_bytes = Array.from(new TextEncoder().encode(url));
  allowedUrls.push(url_bytes)
}

const id = Math.floor(Math.random() * 9999999999);

const attData = JSON.parse(obj.public_data[0].attestation.data);

const bb = await Barretenberg.new();
const hashedUrls: bigint[] = [];

for (let url of allowedUrls) {
  url = url.slice();
  // pad with zeros to length 1024
  while (url.length < 1024) {
    url.push(0);
  }

  // inputs in bb.poseidon2Hash is now Uint8Array[]
  const frArray = url.map(b => new Fr(BigInt(b)).toBuffer());
  const hashFr = await bb.poseidon2Hash({ inputs: frArray });
  const hashBigInt = BigInt(Fr.fromBuffer(hashFr.hash).toString());
  hashedUrls.push(hashBigInt);
}

let H = { x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n, 
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n, 
  is_infinite: false };
  
// deploy business program
// this also initialized the contract storage with admin, allowed_url_hashes and point H
const businessProgram = await BusinessProgramContract.deploy(wallet, alice.address, hashedUrls, H)
  .send({ from: aliceAccount.address })
  .deployed();
console.log("deployed business program");

// Prepare inputs wrt Pederson commitment

// Converts a 32-byte array to a scalar (bigint), matching Rust's bytes2scalar.
function bytes32ToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error("Expected 32 bytes");
  }
  
  const limbs: bigint[] = [];
  
  // Process in reverse: chunks of 8 bytes from end to start
  for (let i = 3; i >= 0; i--) {
    const start = i * 8;
    const chunk = bytes.slice(start, start + 8);
    let limb = 0n;
    for (let j = 0; j < 8; j++) {
      limb = (limb << 8n) | BigInt(chunk[j]);
    }
    limbs.push(limb);
  }
  
  // Reconstruct the 256-bit number from limbs
  let result = 0n;
  for (let i = 0; i < 4; i++) {
    result = result | (limbs[i] << BigInt(i * 64));
  }
  
  return result;
}

// Generates the basis of 2^i powers as bigints for batch_size elements.
function generateExp(batchSize: number): bigint[] {
  const vec: bigint[] = [];
  for (let i = 0; i < batchSize; i++) {
    const j = Math.floor(i / 8);
    const k = i % 8;
    const bytes = new Uint8Array(32);
    bytes[31 - j] |= 1 << k;
    
    const scalar = bytes32ToBigInt(bytes);
    vec.push(scalar);
  }
  return vec;
}

// Splits a JSON response string into field element chunks using bit packing.
// Matches the Rust split_json_response function.
function computeMsgsChunks(jsonResponse: string, batchSize: number): bigint[] {
  // Convert string to bytes and reverse
  let bytes = Array.from(new TextEncoder().encode(jsonResponse));
  bytes.reverse();
  
  // Expand bytes into bits (LSB first for each byte)
  const bits: boolean[] = [];
  for (const byte of bytes) {
    for (let i = 0; i < 8; i++) {
      const b = (byte >> i) & 1;
      bits.push(b !== 0);
    }
  }
  
  // Generate the basis (powers of 2)
  const exp = generateExp(batchSize);
  
  // Create chunks - each chunk encodes batchSize bits
  const vec: bigint[] = [];
  const chunkLen = Math.ceil(bits.length / batchSize);
  let index = 0;
  
  for (let _ = 0; _ < chunkLen; _++) {
    let scalar = 0n;
    for (let j = 0; j < batchSize; j++) {
      if (index >= bits.length) {
        break;
      }
      if (bits[index]) {
        scalar = scalar + exp[j];
      }
      index++;
    }
    vec.push(scalar);
  }
  
  return vec;
}

// Since for this example the msg length is ~200 bytes, there are 7 Field elms
// rnds (7 scalars)
const rnds = obj.private_data[0].random.map((hex: string) => BigInt("0x" + hex));

const attDataParsed = JSON.parse(obj.public_data[0].attestation.data);
const verificationArray = JSON.parse(attDataParsed["#verification_id"]);

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}

const coms = verificationArray.map((hex: string) => {
  const bytes = Buffer.from(hex, "hex");

  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new Error("Expected uncompressed EC point (04 | x | y)");
  }

  const xBytes = new Uint8Array(bytes.slice(1, 33));
  const yBytes = new Uint8Array(bytes.slice(33, 65));

  return {
    x: bytesToBigInt(xBytes),
    y: bytesToBigInt(yBytes),
    is_infinite: false,
  };
});

// Get the full content string (includes wrapper structure)
const content = obj.private_data[0].content;

// Compute message chunks
// With 200 bytes = 1600 bits and batchSize=253: ceil(1600/253) = 7 chunks
const msgs_chunks = computeMsgsChunks(content, GRUMPKIN_BATCH_SIZE);

// Extract reveal string for msgs array
let reveal_json_raw = attData["#reveal_id"];
if (typeof reveal_json_raw === "string") {
  try {
    reveal_json_raw = JSON.parse(reveal_json_raw);
  } catch {
    throw new Error("Invalid JSON in #reveal_id");
  }
}
const reveal_str = JSON.stringify(reveal_json_raw);
const msgs = Array.from(Buffer.from(reveal_str, "utf8"));

const start = performance.now();

let result = await attVerifierContract.methods.verify_attestation(
  public_key_x,
  public_key_y,
  hash,
  signature,
  requestUrls,
  allowedUrls,
  coms,
  rnds,
  msgs_chunks,
  msgs,
  H,
  businessProgram.address,
  id
).send({ from: aliceAccount.address }).wait();

const end = performance.now();
const duration = (end - start).toFixed(2);

console.log(result);
console.log(`Verification call took ${duration} ms`);

if (result.status != "success") {
  console.log("verification failed");
}

// TODO - update get public event
// const success_event = await getDecodedPublicEvents<SuccessEvent>(
//   node,
//   AttVerifierContract.events.SuccessEvent,
//   result.blockNumber!,
//   2
// );
// console.log("Get success event: ", success_event);
await bb.destroy()

// ====================== test update url ===========================
// uncomment below to test update url
// // update url to only https://github.com
// const new_hashedUrls: bigint[] = [];
// // pad with zeros to length 1024
// const github_url = allowedUrls[2];
// while (github_url.length < 1024) {
//   github_url.push(0);
// }
// const frArray = github_url.map(b => new Fr(BigInt(b)));
// const hashFr = await bb.poseidon2Hash(frArray);
// const hashBigInt = BigInt(hashFr.toString());
// new_hashedUrls.push(hashBigInt);
// new_hashedUrls.push(hashBigInt);
// new_hashedUrls.push(hashBigInt);

// // Bob shouldn't be able to update the urls
// try {
//   result = await businessProgram.methods.update_allowed_url_hashes(new_hashedUrls).send({ from: bobAccount.address }).wait();
//   console.log("Error: Bob update the urls");
// } catch (error: unknown) {
//   console.log("Admin verification succeed")
// }
// // Alice (admin) updated the urls to only github.com
// result = await businessProgram.methods.update_allowed_url_hashes(new_hashedUrls).send({ from: aliceAccount.address }).wait();
// console.log(result);
// console.log("Alice updated the urls");

// try {
//   result = await attVerifierContract.methods.verify_attestation(
//     public_key_x,
//     public_key_y,
//     hash,
//     signature,
//     requestUrls,
//     allowedUrls,
//     data_hashes,
//     plain_json_response,
//     businessProgram.address,
//     id
//   ).send({ from: aliceAccount.address }).wait();
//   console.log("url update failed")
// } catch {
//   console.log("url update succeed")
// }