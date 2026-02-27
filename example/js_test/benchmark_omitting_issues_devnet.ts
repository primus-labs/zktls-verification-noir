import fs from "fs";
import { parseAttestationData, parseHashingData, hashUrlsWithPoseidon2 } from "att-verifier-parsing";
import { EmbeddedWallet } from '@aztec/wallets/embedded';
import { BusinessProgramContract, SuccessEvent } from "./bindings/BusinessProgram.js";
import { BusinessProgramSmallCommContract, SuccessEvent as SuccessEventSmallComm } from "./bindings/BusinessProgramSmallComm.js";
import { performance } from "perf_hooks";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { Barretenberg } from "@aztec/bb.js";
import { getPublicEvents } from '@aztec/aztec.js/events';
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { SponsoredFPCContract } from "@aztec/noir-contracts.js/SponsoredFPC";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { getContractInstanceFromInstantiationParams } from '@aztec/stdlib/contract';
import { deriveSigningKey } from '@aztec/stdlib/keys';
import { Fr, BlockNumber } from "@aztec/aztec.js/fields";
import { TxExecutionResult } from "@aztec/stdlib/tx";

// SETUP

const DEVNET_NODE_URL = "https://v4-devnet-2.aztec-labs.com";
const DEPLOY_TIMEOUT = 1200000; // 20 minutes
const TX_TIMEOUT = 180000;      // 3 minutes

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH_COMM = "testdata/attestation_data_grumpkin.json";
const ATT_PATH_COMM_SMALL = "testdata/attestation_data_grumpkin_small.json";
const ATT_PATH_HASH = "testdata/eth_hash.json";
const GRUMPKIN_BATCH_SIZE = 253;

async function getSponsoredFPCInstance() {
  const SPONSORED_FPC_SALT = new Fr(0n);
  return await getContractInstanceFromInstantiationParams(SponsoredFPCContract.artifact, {
    salt: SPONSORED_FPC_SALT,
  });
}

// MEGA TODO is the prover off?!?!?
async function setupWallet() {
  const node = createAztecNodeClient(DEVNET_NODE_URL);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true, pxeConfig: { proverEnabled: true } });
  return wallet;
}

async function deploySchnorrAccount(wallet: EmbeddedWallet) {
  console.log('👤 Deploying Schnorr account...');

  // Generate account keys
  let secretKey = Fr.random();
  let salt = Fr.random();
  let signingKey = deriveSigningKey(secretKey);

  console.log(`🔑 Secret key: ${secretKey.toString()}`);
  console.log(`🧂 Salt: ${salt.toString()}`);
  console.log('⚠️  Save these keys if you want to reuse this account!');

  const account = await wallet.createSchnorrAccount(secretKey, salt, signingKey);
  console.log(`Account address: ${account.address}`);

  const deployMethod = await account.getDeployMethod();

  // Setup sponsored FPC for account deployment
  const sponsoredFPC = await getSponsoredFPCInstance();
  await wallet.registerContract(sponsoredFPC, SponsoredFPCContract.artifact);
  const sponsoredPaymentMethod = new SponsoredFeePaymentMethod(sponsoredFPC.address);

  console.log('⏳ Deploying account on-chain (this takes ~2-5 minutes)...');
  await deployMethod.send({
    from: AztecAddress.ZERO,
    fee: { paymentMethod: sponsoredPaymentMethod },
    skipClassPublication: true,
    skipInstancePublication: true,
    wait: { timeout: 120 },
  });

  console.log(`✅ Account deployed!`);
  return account;
}

// MAIN BENCHMARK

console.log("=".repeat(80));
console.log("ATTESTATION VERIFICATION BENCHMARK - DEVNET");
console.log("=".repeat(80));

// Connect to devnet node
console.log(`Connecting to Aztec node at: ${DEVNET_NODE_URL}`);
const node = createAztecNodeClient(DEVNET_NODE_URL);

// Setup wallet for devnet
console.log("Setting up wallet...");
const wallet = await setupWallet();
console.log("✅ Wallet setup complete");

// Deploy account on devnet
const alice = await deploySchnorrAccount(wallet);

// Setup sponsored FPC for fee payment
console.log("💰 Setting up sponsored fee payment...");
const sponsoredFPC = await getSponsoredFPCInstance();
await wallet.registerContract(sponsoredFPC, SponsoredFPCContract.artifact);
const sponsoredPaymentMethod = new SponsoredFeePaymentMethod(sponsoredFPC.address);
console.log(`✅ Sponsored FPC configured at: ${sponsoredFPC.address}`);

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

console.log("[3/4] Deploying business program contract to devnet...");
console.log("(This may take up to 20 minutes on devnet...)");
const startDeploy1 = performance.now();
const businessProgramComm = await BusinessProgramContract.deploy(
  wallet,
  alice.address,
  hashedUrlsComm,
  H
)
  .send({
    from: alice.address,
    fee: { paymentMethod: sponsoredPaymentMethod },
    wait: { timeout: DEPLOY_TIMEOUT }
  });
const endDeploy1 = performance.now();
console.log("Contract deployed at:", businessProgramComm.address.toString());

console.log("[4/4] Verifying attestation with commitments...");
const startComm = performance.now();

// Commented out - uncomment when ready to verify
let resultComm = await businessProgramComm.methods.__aztec_nr_internals__verify_comm(
  parsedComm.publicKeyX,
  parsedComm.publicKeyY,
  parsedComm.hash,
  parsedComm.signature,
  parsedComm.requestUrls,
  parsedComm.allowedUrls,
  parsedComm.commitments,
  parsedComm.randomScalars,
  parsedComm.msgsChunks,
  parsedComm.msgs,
  H,
  parsedComm.id
).send({
  from: alice.address,
  fee: { paymentMethod: sponsoredPaymentMethod },
  wait: { timeout: TX_TIMEOUT }
});

const endComm = performance.now();
const durationComm = (endComm - startComm).toFixed(2);

console.log("\n" + "-".repeat(80));
console.log("COMMITMENT VERIFICATION RESULTS:");
console.log("-".repeat(80));
console.log("Status:", resultComm.status);
console.log("Verification time:", durationComm, "ms");
console.log("Block number:", resultComm.blockNumber);

if (resultComm.executionResult === TxExecutionResult.SUCCESS) {
  const success_event_comm = await getPublicEvents<SuccessEvent>(
    node,
    BusinessProgramContract.events.SuccessEvent,
    { fromBlock: BlockNumber(resultComm.blockNumber!), contractAddress: businessProgramComm.address }
  );
  console.log("Success event:", success_event_comm.length > 0 ? "OK - Event emitted" : "Not found");
} else {
  console.log("Verification failed");
}

// =============================================================================
// TEST 1b: COMMITMENT-BASED VERIFICATION (SMALL)
// =============================================================================
console.log("\n" + "=".repeat(80));
console.log("TEST 1b: COMMITMENT-BASED VERIFICATION (SMALL)");
console.log("=".repeat(80));

// Load small commitment attestation data
const attestationDataCommSmall = JSON.parse(fs.readFileSync(ATT_PATH_COMM_SMALL, "utf-8"));

console.log("\n[1/4] Parsing attestation data (small)...");
const parsedCommSmall = parseAttestationData(attestationDataCommSmall, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("[2/4] Hashing allowed URLs...");
const hashedUrlsCommSmall = await hashUrlsWithPoseidon2(bb, parsedCommSmall.allowedUrls);

console.log("[3/4] Deploying business program contract (small) to devnet...");
console.log("(This may take up to 20 minutes on devnet...)");
const startDeploy2 = performance.now();

const businessProgramSmallComm = await BusinessProgramSmallCommContract.deploy(
  wallet,
  alice.address,
  hashedUrlsCommSmall,
  H
)
  .send({
    from: alice.address,
    fee: { paymentMethod: sponsoredPaymentMethod },
    wait: { timeout: DEPLOY_TIMEOUT }
  });

const endDeploy2 = performance.now();
console.log(`Contract deployed at: ${businessProgramSmallComm.address.toString()}`);

console.log("[4/4] Verifying attestation with commitments (small)...");
const startCommSmall = performance.now();

let resultCommSmall = await businessProgramSmallComm.methods.__aztec_nr_internals__verify_comm(
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
).send({
  from: alice.address,
  fee: { paymentMethod: sponsoredPaymentMethod },
  wait: { timeout: TX_TIMEOUT }
});

const endCommSmall = performance.now();
const durationCommSmall = (endCommSmall - startCommSmall).toFixed(2);

console.log("\n" + "-".repeat(80));
console.log("COMMITMENT VERIFICATION RESULTS (SMALL):");
console.log("-".repeat(80));
console.log("Status:", resultCommSmall.status);
console.log("Verification time:", durationCommSmall, "ms");
console.log("Block number:", resultCommSmall.blockNumber);

if (resultCommSmall.executionResult === TxExecutionResult.SUCCESS) {
  const success_event_comm_small = await getPublicEvents<SuccessEventSmallComm>(
    node,
    BusinessProgramSmallCommContract.events.SuccessEvent,
    { fromBlock: BlockNumber(resultCommSmall.blockNumber!), contractAddress: businessProgramSmallComm.address }
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

let resultHash = await businessProgramComm.methods.__aztec_nr_internals__verify_hash(
  parsedHash.publicKeyX,
  parsedHash.publicKeyY,
  parsedHash.hash,
  parsedHash.signature,
  parsedHash.requestUrls,
  parsedHash.allowedUrls,
  parsedHash.dataHashes,
  parsedHash.plainJsonResponses,
  parsedHash.id
).send({
  from: alice.address,
  fee: { paymentMethod: sponsoredPaymentMethod },
  wait: { timeout: TX_TIMEOUT }
});

const endHash = performance.now();
const durationHash = (endHash - startHash).toFixed(2);

console.log("\n" + "-".repeat(80));
console.log("HASH VERIFICATION RESULTS:");
console.log("-".repeat(80));
console.log("Status:", resultHash.status);
console.log("Verification time:", durationHash, "ms");
console.log("Block number:", resultHash.blockNumber);

if (resultHash.executionResult === TxExecutionResult.SUCCESS) {
  const success_event_hash = await getPublicEvents<SuccessEvent>(
    node,
    BusinessProgramContract.events.SuccessEvent,
    { fromBlock: BlockNumber(resultHash.blockNumber!), contractAddress: businessProgramComm.address }
  );
  console.log("Success event:", success_event_hash.length > 0 ? "OK - Event emitted" : "Not found");
} else {
  console.log("Verification failed");
}

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
process.exit(0);
