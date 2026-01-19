import fs from "fs";
import { parseAttestationData, parseHashingData, hashUrlsWithPoseidon2 } from "att-verifier-parsing";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { TestWallet } from "@aztec/test-wallet/server";
import { getPXEConfig } from "@aztec/pxe/server";
import { BusinessProgramContract, SuccessEvent } from "./bindings/BusinessProgram.js";
import { BusinessProgramSmallCommContract, SuccessEvent as SuccessEventSmallComm } from "./bindings/BusinessProgramSmallComm.js";
import { performance } from "perf_hooks";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { rm } from "node:fs/promises";
import { Barretenberg } from "@aztec/bb.js";
import { getDecodedPublicEvents } from '@aztec/aztec.js/events';
import { Fr } from "@aztec/aztec.js/fields";

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH_COMM = "testdata/attestation_data_grumpkin.json";
const ATT_PATH_COMM_SMALL = "testdata/attestation_data_grumpkin_small.json";
const ATT_PATH_HASH = "testdata/eth_hash.json";
const GRUMPKIN_BATCH_SIZE = 253;

console.log("=".repeat(80));
console.log("ATTESTATION VERIFICATION BENCHMARK");
console.log("=".repeat(80));

const node = createAztecNodeClient("http://localhost:8080");

const config = getPXEConfig();
await rm("pxe", { recursive: true, force: true });
config.dataDirectory = "pxe";
config.proverEnabled = true;
const wallet = await TestWallet.create(node, config);
const [aliceAccount] = await getInitialTestAccountsData();
let alice = await wallet.createSchnorrAccount(aliceAccount.secret, aliceAccount.salt);

const bb = await Barretenberg.new();

// =============================================================================
// TEST 1: COMMITMENT-BASED VERIFICATION
// =============================================================================
console.log("\n" + "=".repeat(80));
console.log("TEST 1: COMMITMENT-BASED VERIFICATION (Pedersen)");
console.log("=".repeat(80));

// Load commitment attestation data
const attestationDataComm = JSON.parse(fs.readFileSync(ATT_PATH_COMM, "utf-8"));

console.log("\n[1/4] Parsing attestation data...");
const parsedComm = parseAttestationData(attestationDataComm, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("[2/4] Hashing allowed URLs...");
const hashedUrlsComm = await hashUrlsWithPoseidon2(bb, parsedComm.allowedUrls);

// Point H for Pedersen commitment
let H = { 
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n, 
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n, 
  is_infinite: false 
};

// console.log("[3/4] Deploying business program contract...");
// const businessProgramComm = await BusinessProgramContract.deploy(
//   wallet, 
//   alice.address, 
//   hashedUrlsComm, 
//   H
// )
//   .send({ from: aliceAccount.address })
//   .deployed();
// console.log("Contract deployed at:", businessProgramComm.address.toString());

// console.log("[4/4] Verifying attestation with commitments...");
// const startComm = performance.now();

// let resultComm = await businessProgramComm.methods.verify_comm(
//   parsedComm.publicKeyX,
//   parsedComm.publicKeyY,
//   parsedComm.hash,
//   parsedComm.signature,
//   parsedComm.requestUrls,
//   parsedComm.allowedUrls,
//   parsedComm.commitments,
//   parsedComm.randomScalars,
//   parsedComm.msgsChunks,
//   parsedComm.msgs,
//   H,
//   parsedComm.id
// ).send({ from: aliceAccount.address }).wait();

// const endComm = performance.now();
// const durationComm = (endComm - startComm).toFixed(2);

// console.log("\n" + "-".repeat(80));
// console.log("COMMITMENT VERIFICATION RESULTS:");
// console.log("-".repeat(80));
// console.log("Status:", resultComm.status);
// console.log("Verification time:", durationComm, "ms");
// console.log("Block number:", resultComm.blockNumber);

// if (resultComm.status === "success") {
//   const success_event_comm = await getDecodedPublicEvents<SuccessEvent>(
//     node,
//     BusinessProgramContract.events.SuccessEvent,
//     resultComm.blockNumber!,
//     2
//   );
//   console.log("Success event:", success_event_comm.length > 0 ? "OK - Event emitted" : "Not found");
// } else {
//   console.log("Verification failed");
// }

// =============================================================================
// TEST 1b: COMMITMENT-BASED VERIFICATION (SMALL)
// =============================================================================
console.log("\n" + "=".repeat(80));
console.log("TEST 1b: COMMITMENT-BASED VERIFICATION (SMALL)");
console.log("=".repeat(80));

// Load small commitment attestation data
const attestationDataCommSmall = JSON.parse(fs.readFileSync(ATT_PATH_COMM_SMALL, "utf-8"));

console.log("\n[1/2] Parsing attestation data (small)...");
const parsedCommSmall = parseAttestationData(attestationDataCommSmall, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("[2/4] Hashing allowed URLs...");
const hashedUrlsCommSmall = await hashUrlsWithPoseidon2(bb, parsedCommSmall.allowedUrls);

console.log("[3/4] Deploying business program contract (small)...");
const businessProgramSmallComm = await BusinessProgramSmallCommContract.deploy(
  wallet, 
  alice.address, 
  hashedUrlsCommSmall, 
  H
)
  .send({ from: aliceAccount.address })
  .deployed();
console.log("Contract deployed at:", businessProgramSmallComm.address.toString());

console.log("[4/4] Verifying attestation with commitments (small)...");
const startCommSmall = performance.now();

let resultCommSmall = await businessProgramSmallComm.methods.verify_comm(
  parsedCommSmall.publicKeyX,
  parsedCommSmall.publicKeyY,
  parsedCommSmall.hash,
  parsedCommSmall.signature,
  parsedCommSmall.requestUrls,
  parsedCommSmall.allowedUrls,
  parsedCommSmall.commitments,
  parsedCommSmall.randomScalars,
  parsedCommSmall.msgsChunks,
  parsedCommSmall.msgs,
  H,
  parsedCommSmall.id
).send({ from: aliceAccount.address }).wait();

const endCommSmall = performance.now();
const durationCommSmall = (endCommSmall - startCommSmall).toFixed(2);

console.log("\n" + "-".repeat(80));
console.log("COMMITMENT VERIFICATION RESULTS (SMALL):");
console.log("-".repeat(80));
console.log("Status:", resultCommSmall.status);
console.log("Verification time:", durationCommSmall, "ms");
console.log("Block number:", resultCommSmall.blockNumber);

if (resultCommSmall.status === "success") {
  const success_event_comm_small = await getDecodedPublicEvents<SuccessEventSmallComm>(
    node,
    BusinessProgramSmallCommContract.events.SuccessEvent,
    resultCommSmall.blockNumber!,
    2
  );
  console.log("Success event:", success_event_comm_small.length > 0 ? "OK - Event emitted" : "Not found");
} else {
  console.log("Verification failed");
}

// =============================================================================
// TEST 2: HASH-BASED VERIFICATION
// =============================================================================
console.log("\n" + "=".repeat(80));
console.log("TEST 2: HASH-BASED VERIFICATION");
console.log("=".repeat(80));

// Load hashing attestation data
const attestationDataHash = JSON.parse(fs.readFileSync(ATT_PATH_HASH, "utf-8"));

console.log("\n[1/3] Parsing attestation data (hash approach)...");
const parsedHash = parseHashingData(attestationDataHash, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("[2/3] Hashing allowed URLs...");
const hashedUrlsHash = await hashUrlsWithPoseidon2(bb, parsedHash.allowedUrls);

console.log("[3/3] Verifying attestation with hashing...");
const startHash = performance.now();

// let resultHash = await businessProgramComm.methods.verify_hash(
//   parsedHash.publicKeyX,
//   parsedHash.publicKeyY,
//   parsedHash.hash,
//   parsedHash.signature,
//   parsedHash.requestUrls,
//   parsedHash.allowedUrls,
//   parsedHash.dataHashes,
//   parsedHash.plainJsonResponses,
//   parsedHash.id
// ).send({ from: aliceAccount.address }).wait();

// const endHash = performance.now();
// const durationHash = (endHash - startHash).toFixed(2);

// console.log("\n" + "-".repeat(80));
// console.log("HASH VERIFICATION RESULTS:");
// console.log("-".repeat(80));
// console.log("Status:", resultHash.status);
// console.log("Verification time:", durationHash, "ms");
// console.log("Block number:", resultHash.blockNumber);

// if (resultHash.status === "success") {
//   const success_event_hash = await getDecodedPublicEvents<SuccessEvent>(
//     node,
//     BusinessProgramContract.events.SuccessEvent,
//     resultHash.blockNumber!,
//     2
//   );
//   console.log("Success event:", success_event_hash.length > 0 ? "OK - Event emitted" : "Not found");
// } else {
//   console.log("Verification failed");
// }

// =============================================================================
// SUMMARY
// =============================================================================
console.log("\n" + "=".repeat(80));
console.log("BENCHMARK SUMMARY");
console.log("=".repeat(80));
// console.log(`Commitment-based verification:       ${durationComm} ms`);
console.log(`Commitment-based verification (small): ${durationCommSmall} ms`);
// console.log(`Hash-based verification:             ${durationHash} ms`);
console.log("=".repeat(80));

// Cleanup
await bb.destroy();