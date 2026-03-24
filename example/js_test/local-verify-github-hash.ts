/**
 * local-verify-github-hash.ts
 *
 * Verify a GitHub contributors hash-based attestation on a local Aztec network.
 * Uses github-contributors-attestation.json (HASH_COMPARISON type).
 *
 * Prerequisites: `aztec start --local-network` running on port 8080.
 *
 * Note: the contract's MAX_CONTENT_LEN is 1000 bytes but the GitHub contributors
 * response is ~1847 bytes. The verify_hash call may fail at the SHA256 check
 * unless the contract is recompiled with a larger MAX_CONTENT_LEN.
 */

import fs from "fs";
import { parseHashingData, hashUrlsWithPoseidon2 } from "att-verifier-parsing";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { BusinessProgramContract } from "./bindings/BusinessProgram_github.js";
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
const ATT_PATH = "testdata/github-contributors-attestation.json";
const GRUMPKIN_BATCH_SIZE = 253;

// The contributor to verify from the attestation response
const GITHUB_USERNAME = "ewynx";
const CONTRIBUTOR_INDEX = 0;

// This is only needed because the example contract does commitment and has based in one
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
console.log("local verify_hash — GitHub contributors (HASH_COMPARISON)");
console.log("=".repeat(70));
console.log(`Connecting to local network at ${LOCAL_NODE_URL}`);
console.log("Make sure 'aztec start --local-network' is running!\n");

const bb = await Barretenberg.new();
const { node, wallet } = await setupWallet();
const account = await getTestAccount(wallet);

const rawData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseHashingData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

const hashedUrls = await hashUrlsWithPoseidon2(bb, parsed.allowedUrls);

const githubUsernameBytes = Array.from(new TextEncoder().encode(GITHUB_USERNAME));

console.log("\nDeploying BusinessProgram contract...");
const contract = await BusinessProgramContract.deploy(wallet, account.address, hashedUrls, H)
  .send({ from: account.address, wait: { timeout: DEPLOY_TIMEOUT } });
console.log("Contract deployed at:", contract.address.toString());

console.log("\nProfiling verify_hash...");
const profile = await contract.methods.verify_hash(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.dataHashes, parsed.plainJsonResponses,
  parsed.id, githubUsernameBytes, CONTRIBUTOR_INDEX,
).profile({ from: account.address, profileMode: "full", skipProofGeneration: true });

for (const s of profile.executionSteps) {
  console.log(`  ${s.functionName}: ${s.gateCount?.toLocaleString()} gates`);
}

console.log("\nExecuting verify_hash on-chain...");
const start = Date.now();
const result = await contract.methods.verify_hash(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.dataHashes, parsed.plainJsonResponses,
  parsed.id, githubUsernameBytes, CONTRIBUTOR_INDEX,
).send({ from: account.address, wait: { timeout: TX_TIMEOUT } });

console.log(`\nTransaction confirmed!`);
console.log(`   Status:       ${result.status}`);
console.log(`   Block number: ${result.blockNumber}`);
console.log(`   Duration:     ${((Date.now() - start) / 1000).toFixed(1)}s`);

const events = await getPublicEvents<{ sender: unknown, contract_address: unknown, id: bigint }>(node, BusinessProgramContract.events.SuccessEvent, {
  txHash: result.txHash,
  contractAddress: contract.address,
});
if (events.length === 0) throw new Error("SuccessEvent was NOT emitted!");
console.log(`   SuccessEvent:  emitted (id=${events[0].event.id})`);

await bb.destroy();
process.exit(0);
