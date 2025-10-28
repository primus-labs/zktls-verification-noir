
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
import { createAztecNodeClient } from "@aztec/aztec.js";
import { Barretenberg, Fr } from "@aztec/bb.js";

const node = createAztecNodeClient("http://localhost:8080");
const l1Contracts = await node.getL1ContractAddresses();

const config = getPXEConfig();
const fullConfig = { ...config, l1Contracts };
fullConfig.proverEnabled = true;

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


// deploy attVerifierContract
const attVerifierContract = await AttVerifierContract.deploy(wallet).send({ from: aliceAccount.address })
  .deployed();
console.log("deployed attverifier");

// load attestation testdata
const obj = JSON.parse(fs.readFileSync("testdata/attestation_data_hash.json", "utf-8"));

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
const urlStr0: string = obj.public_data[0].attestation.request[0].url;
const urlStr1: string = obj.public_data[0].attestation.request[1].url;
const urlBytes0 = Array.from(new TextEncoder().encode(urlStr0));
const urlBytes1 = Array.from(new TextEncoder().encode(urlStr1));

// for allowed urls
const url_extra_bytes = Array.from(new TextEncoder().encode("https://github.com"));

const requestUrls: (bigint | number)[][] = [
  urlBytes0,
  urlBytes1
];

const allowedUrls = [
  urlBytes0,
  urlBytes1,
  url_extra_bytes
];

const id = Math.floor(Math.random() * 9999999999);

// Collect all hashes from public_data.attestation.data
const data_hashes: number[][] = [];
const attData = JSON.parse(obj.public_data[0].attestation.data);
for (const [key, value] of Object.entries(attData)) {
  if (key.startsWith("uuid-") && typeof value === "string" && value.length === 64) {
    // Convert each 32-byte hex string into an array of bytes
    const hashBytes = Array.from(Buffer.from(value, "hex"));
    data_hashes.push(hashBytes);
  }
}

const plain_json_response: number[][] = [];

if (obj.private_data && Array.isArray(obj.private_data.plain_json_response)) {
  for (const entry of obj.private_data.plain_json_response) {
    if (entry.id && entry.content) {
      const jsonBytes = Array.from(new TextEncoder().encode(entry.content));
      plain_json_response.push(jsonBytes);
    }
  }
}

const bb = await Barretenberg.new();
const hashedUrls: bigint[] = [];

for (const url of allowedUrls) {
  // pad with zeros to length 1024
  while (url.length < 1024) {
    url.push(0);
  }

  const frArray = url.map(b => new Fr(BigInt(b)));
  const hashFr = await bb.poseidon2Hash(frArray);
  const hashBigInt = BigInt(hashFr.toString());
  hashedUrls.push(hashBigInt);
}

// deploy business program
const businessProgram = await BusinessProgramContract.deploy(wallet, alice.address, hashedUrls)
  .send({ from: aliceAccount.address }) // testAccount has fee juice and is registered in the deployer_wallet
  .deployed();
console.log("deployed business program");

const start = performance.now();
let result = await attVerifierContract.methods.verify_attestation(
  public_key_x,
  public_key_y,
  hash,
  signature,
  requestUrls,
  allowedUrls,
  data_hashes,
  plain_json_response,
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

// update url to only https://github.com
const new_hashedUrls: bigint[] = [];
// pad with zeros to length 1024
const github_url = allowedUrls[2];
while (github_url.length < 1024) {
  github_url.push(0);
}
const frArray = github_url.map(b => new Fr(BigInt(b)));
const hashFr = await bb.poseidon2Hash(frArray);
const hashBigInt = BigInt(hashFr.toString());
new_hashedUrls.push(hashBigInt);
new_hashedUrls.push(hashBigInt);
new_hashedUrls.push(hashBigInt);

// Bob shouldn't be able to update the urls
try {
  result = await businessProgram.methods.update_allowed_url_hashes(new_hashedUrls).send({ from: bobAccount.address }).wait();
  console.log("Error: Bob update the urls");
} catch (error: unknown) {
  console.log("Admin verification succeed")
}
// Alice (admin) updated the urls to only github.com
result = await businessProgram.methods.update_allowed_url_hashes(new_hashedUrls).send({ from: aliceAccount.address }).wait();
console.log(result);
console.log("Alice updated the urls");

try {
  result = await attVerifierContract.methods.verify_attestation(
    public_key_x,
    public_key_y,
    hash,
    signature,
    requestUrls,
    allowedUrls,
    data_hashes,
    plain_json_response,
    businessProgram.address,
    id
  ).send({ from: aliceAccount.address }).wait();
  console.log("url update failed")
} catch {
  console.log("url update succeed")
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
