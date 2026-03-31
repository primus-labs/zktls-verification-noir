/**
 * local-verify-github-comm.ts
 *
 * Verify a GitHub contributors commitment-based attestation on a local Aztec network.
 * Uses github-contributors-attestation-commitment.json (GRUMPKIN_COMMITMENT type).
 *
 * Prerequisites: `aztec start --local-network` running on port 8080.
 */

import fs from "fs";
import { parseCommitmentData } from "att-verifier-parsing";
import { GithubVerifierContract, type SuccessEvent } from "./bindings/GithubVerifier.ts";
import { Client, ContractHelpers } from "aztec-attestation-sdk";
import { getPublicEvents } from "@aztec/aztec.js/events";

// Config

const LOCAL_NODE_URL = "http://localhost:8080";
const DEPLOY_TIMEOUT = 300000; // 5 min
const TX_TIMEOUT = 120000;     // 2 min

const MAX_RESPONSE_NUM = 2;
const MAX_URL_LEN = 128;
const ALLOWED_URLS = ["https://api.github.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/github-contributors-attestation-commitment.json";
const GRUMPKIN_BATCH_SIZE = 253;

// The contributor to verify from the attestation response
const GITHUB_USERNAME = "ewynx";
const GITHUB_ID = "22170967";

const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false,
};

// Main

console.log("=".repeat(70));
console.log("local verify_comm — GitHub contributors (GRUMPKIN_COMMITMENT)");
console.log("=".repeat(70));
console.log(`Connecting to local network at ${LOCAL_NODE_URL}`);
console.log("Make sure 'aztec start --local-network' is running!\n");

const client = new Client({ nodeUrl: LOCAL_NODE_URL });
await client.initialize();
const account = await client.getAccount(0);
console.log(`Using test account: ${account.address}`);

const rawData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseCommitmentData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URLS,
  maxUrlLen: MAX_URL_LEN,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});
console.log(`Commitments in test data: ${parsed.coms_per_group.length}`);

console.log("\nDeploying GithubVerifier contract...");
const contract = await ContractHelpers.deployContract(GithubVerifierContract, client, {
  admin: account.address,
  allowedUrls: ALLOWED_URLS,
  maxUrlLen: MAX_URL_LEN,
  pointH: H,
  from: account.address,
  timeout: DEPLOY_TIMEOUT,
});
console.log("Contract deployed at:", contract.address.toString());

const githubUsernameBytes = Array.from(new TextEncoder().encode(GITHUB_USERNAME));
const githubId = Array.from(new TextEncoder().encode(GITHUB_ID));

console.log("\nProfiling verify_comm...");
  // SchnorrAccount:entrypoint: 54,502 gates
  // private_kernel_init: 46,811 gates
  // GithubVerifier:verify_comm: 91,497 gates
  // private_kernel_inner: 101,237 gates
  // private_kernel_reset: 112,535 gates
  // private_kernel_tail: 88,998 gates
  // hiding_kernel: 38,069 gates
const profile = await contract.methods.verify_comm(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, 
  parsed.coms_per_group, 
  parsed.rnds_per_group, 
  parsed.msgs_chunks_per_group, 
  parsed.msgs_per_group, 
  H, parsed.id, githubUsernameBytes, githubId
).profile({ from: account.address, profileMode: "full", skipProofGeneration: true });

for (const s of profile.executionSteps) {
  console.log(`  ${s.functionName}: ${s.gateCount?.toLocaleString()} gates`);
}

console.log("\nExecuting verify_comm on-chain...");
const start = Date.now();
const { receipt } = await contract.methods.verify_comm(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, 
  parsed.coms_per_group, 
  parsed.rnds_per_group, 
  parsed.msgs_chunks_per_group, 
  parsed.msgs_per_group, 
  H, parsed.id, githubUsernameBytes, githubId
).send({ from: account.address, wait: { timeout: TX_TIMEOUT } });

console.log(`\nTransaction confirmed!`);
console.log(`   Status:       ${receipt.status}`);
console.log(`   Block number: ${receipt.blockNumber}`);
console.log(`   Duration:     ${((Date.now() - start) / 1000).toFixed(1)}s`);

const { events } = await getPublicEvents<SuccessEvent>(
  client.getNode(), GithubVerifierContract.events.SuccessEvent, { txHash: receipt.txHash, contractAddress: contract.address }
);
if (events.length === 0) throw new Error("SuccessEvent was NOT emitted!");
console.log(`   SuccessEvent:  emitted (id=${events[0].event.id})`);

await client.cleanup();
process.exit(0);
