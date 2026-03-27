/**
 * local-verify-github-comm.ts
 *
 * Verify a GitHub contributors commitment-based attestation on a local Aztec network.
 * Uses github-contributors-commitment-attestation.json (GRUMPKIN_COMMITMENT type).
 *
 * Prerequisites: `aztec start --local-network` running on port 8080.
 */

import fs from "fs";
import { parseCommitmentData, hashUrlsWithPoseidon2 } from "att-verifier-parsing";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { OKXVerifierContract } from "./bindings/OKXVerifier.js";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { getPublicEvents } from "@aztec/aztec.js/events";
import { Barretenberg } from "@aztec/bb.js";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";

// Config

const LOCAL_NODE_URL = "http://localhost:8080";
const DEPLOY_TIMEOUT = 300000; // 5 min
const TX_TIMEOUT = 120000;     // 2 min

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.github.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/okx-attestation-comm.json";
const GRUMPKIN_BATCH_SIZE = 253;

const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false,
};

// Helpers

async function setupWallet() {
  const node = createAztecNodeClient(LOCAL_NODE_URL);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true, pxeConfig: { proverEnabled: false } });
  return { node, wallet };
}

async function getTestAccount(wallet: EmbeddedWallet) {
  const [aliceData] = await getInitialTestAccountsData();
  const account = await wallet.createSchnorrAccount(aliceData.secret, aliceData.salt, aliceData.signingKey);
  console.log(`Using test account: ${account.address}`);
  return account;
}

// Main

console.log("=".repeat(70));
console.log("local verify_comm — OKX (GRUMPKIN_COMMITMENT)");
console.log("=".repeat(70));
console.log(`Connecting to local network at ${LOCAL_NODE_URL}`);
console.log("Make sure 'aztec start --local-network' is running!\n");

const bb = await Barretenberg.new();
const { node, wallet } = await setupWallet();
const account = await getTestAccount(wallet);

const rawData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseCommitmentData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});
console.log(`Commitments in test data: ${parsed.groups.length}`);

const hashedUrls = await hashUrlsWithPoseidon2(bb, parsed.allowedUrls);


console.log("\nDeploying OKXVerifierContract contract...");
const contract = await OKXVerifierContract.deploy(wallet, account.address, hashedUrls, H)
  .send({ from: account.address, wait: { timeout: DEPLOY_TIMEOUT } });
console.log("Contract deployed at:", contract.address.toString());

console.log("\nProfiling verify_comm...");
  // SchnorrAccount:entrypoint: 54,352 gates
  // private_kernel_init: 46,811 gates
  // OKXVerifier:verify_comm: 267,040 gates
  // private_kernel_inner: 101,237 gates
  // private_kernel_reset: 112,535 gates
  // private_kernel_tail: 88,987 gates
  // hiding_kernel: 38,069 gates
const profile = await contract.methods.verify_comm(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.groups[0].commitments, parsed.groups[0].randomScalars, parsed.groups[0].msgsChunks, parsed.groups[0].msgs, 
  H, parsed.id
).profile({ from: account.address, profileMode: "full", skipProofGeneration: true });

for (const s of profile.executionSteps) {
  console.log(`  ${s.functionName}: ${s.gateCount?.toLocaleString()} gates`);
}

console.log("\nExecuting verify_comm on-chain...");
const start = Date.now();
const result = await contract.methods.verify_comm(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.groups[0].commitments, parsed.groups[0].randomScalars, parsed.groups[0].msgsChunks, parsed.groups[0].msgs, 
  H, parsed.id, 
).send({ from: account.address, wait: { timeout: TX_TIMEOUT } });

console.log(`\nTransaction confirmed!`);
console.log(`   Status:       ${result.status}`);
console.log(`   Block number: ${result.blockNumber}`);
console.log(`   Duration:     ${((Date.now() - start) / 1000).toFixed(1)}s`);
const events = await getPublicEvents<{ sender: unknown, contract_address: unknown, id: bigint }>(node, OKXVerifierContract.events.SuccessEvent, {

  txHash: result.txHash,
  contractAddress: contract.address,
});
if (events.length === 0) throw new Error("SuccessEvent was NOT emitted!");
console.log(`   SuccessEvent:  emitted (id=${events[0].event.id})`);

await bb.destroy();
process.exit(0);
