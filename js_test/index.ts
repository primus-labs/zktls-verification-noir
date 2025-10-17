
import fs from "fs";
import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { encodePacked, padTo } from "./lib/encoding";
import { normalizeV } from "./lib/crypto";
import { AttVerifierContract, SuccessEvent } from "./bindings/AttVerifier.js";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { createAztecNodeClient } from "@aztec/aztec.js";
import { TestWallet } from "@aztec/test-wallet/server";
import { createStore } from "@aztec/kv-store/lmdb";
import { createPXE, getPXEConfig, PXE } from "@aztec/pxe/server";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";
import { performance } from "perf_hooks"; 
const node = createAztecNodeClient("http://localhost:8080");
const l1Contracts = await node.getL1ContractAddresses();

const config = getPXEConfig();
const fullConfig = { ...config, l1Contracts };
fullConfig.proverEnabled = false; // you'll want to set this to "true" once you're ready to connect to the testnet

const store = await createStore("pxe", {
  dataDirectory: "store",
  dataStoreMapSizeKB: 1e6,
});
const pxe = await createPXE(node, fullConfig, { store });
// await waitForPXE(pxe);

const wallet = await TestWallet.create(node);
const [aliceAccount, bobAccount] = await getInitialTestAccountsData();
let alice = await wallet.createSchnorrAccount(aliceAccount.secret, aliceAccount.salt);
let bob = await wallet.createSchnorrAccount(bobAccount.secret, bobAccount.salt);

// deploy business program
const businessProgram = await BusinessProgramContract.deploy(wallet)
    .send({ from: aliceAccount.address }) // testAccount has fee juice and is registered in the deployer_wallet
    .deployed();
// deploy attVerifierContract
const attVerifierContract = await AttVerifierContract.deploy(wallet).send({ from: aliceAccount.address })
  .deployed();

// load attestation testdata
const obj = JSON.parse(fs.readFileSync("testdata/attestation_data.json", "utf-8"));

// pack data
const packedArr = encodePacked(obj.public_data);

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

// for allowed urls
const url2_bytes = Array.from(new TextEncoder().encode("https://github.com"));

const allowedUrls = [urlBytes, url2_bytes];

// Get ciphertext data
const dataObj = JSON.parse(obj.public_data.data);
const chrc = JSON.parse(dataObj.CompleteHttpResponseCiphertext);

let allCiphertexts: number[][] = [];
let allNonces: number[][] = [];
let allJsonBlocks: [number, number][] = [];

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
let jsonBlocksFixed: [number, number][] = [];

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
// create random id for this attestation
const id = Math.floor(Math.random() * 9999999999);

const start = performance.now();
let result = await attVerifierContract.methods.verify_attestation(
  public_key_x,
  public_key_y,
  hash,
  signature,
  urlBytes,
  allowedUrls,
  ciphertextsFixed,
  number_of_ciphertexts,
  jsonBlocksFixed,
  noncesFixed,
  aes_key,
  businessProgram.address,
  id
).send({ from: aliceAccount.address }).wait();
// This works for AttVerifier without event emission
const end = performance.now();
const duration = (end - start).toFixed(2);

console.log(result);
console.log(`Verification call took ${duration} ms`);

if (result.status != "success") {
  console.log("verification failed");
}
// pxe.getNotes
// const fromBlock = await pxe.getBlockNumber();
// const logFilter = {
//   fromBlock,
//   toBlock: fromBlock + 1,
// };
// const publicLogs = (await pxe.getPublicLogs(logFilter)).logs;
// // const publicLogs = (await pxe.getPublicEvents(AttVerifierContract.events.SuccessEvent, result.blockNumber as number, result.blockNumber as number));
// for (const log of publicLogs) {
//   if ((log as SuccessEvent).id == id) {
//     console.log("Verification success");
//     console.log(log)
//   }

// }
