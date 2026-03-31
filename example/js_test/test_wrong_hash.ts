// First data hash made incorrect -> tx should fail

import fs from "fs";
import { parseHashingData } from "att-verifier-parsing";
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
const ATT_PATH = "testdata/github-contributors-attestation-hash.json";

// The contributor to verify from the attestation response
const GITHUB_USERNAME = "ewynx";
const GITHUB_ID = "22170967";

// This is only needed because the example contract does commitment and has based in one
const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false,
};

// Main

console.log("=".repeat(70));
console.log("local verify_hash — GitHub contributors (HASH_COMPARISON)");
console.log("=".repeat(70));
console.log(`Connecting to local network at ${LOCAL_NODE_URL}`);
console.log("Make sure 'aztec start --local-network' is running!\n");

const client = new Client({ nodeUrl: LOCAL_NODE_URL });
await client.initialize();
const account = await client.getAccount(0);
console.log(`Using test account: ${account.address}`);

const rawData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseHashingData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URLS,
  maxUrlLen: MAX_URL_LEN,
});

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

console.log("\nExecuting verify_hash on-chain...");
const start = Date.now();
parsed.dataHashes[0] = parsed.dataHashes[1]
try {
  const { receipt } = await contract.methods.verify_hash(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.dataHashes, parsed.plainJsonResponses,
  parsed.id, githubUsernameBytes, githubId,
  ).send({ from: account.address, wait: { timeout: TX_TIMEOUT } });

  console.log(`\nTransaction confirmed (PROBLEM!! - should have failed!)`);
  console.log(`   Status:       ${receipt.status}`);
  console.log(`   Duration:     ${((Date.now() - start) / 1000).toFixed(1)}s`);
  await client.cleanup();
  process.exit(1);
} catch (e) {
  console.log(`\nTransaction failed as expected.`);
  console.log(`   Duration: ${((Date.now() - start) / 1000).toFixed(1)}s`);
  console.log(`   Error: ${e instanceof Error ? e.message : String(e)}`);
  console.log("\nTEST PASSED");
  await client.cleanup();
  process.exit(0);
}
