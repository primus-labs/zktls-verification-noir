/**
 * Test 1b: verify_comm — BusinessProgramSmallComm (MAX_COMMS=1, MAX_MSGS_LEN=50)
 *
 * Profiles and executes the small commitment-based verification on devnet.
 * This variant has a small enough circuit to fit within the ClientIVC kernel floor (2^21).
 */

import fs from "fs";
import { parseAttestationData, hashUrlsWithPoseidon2 } from "att-verifier-parsing";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { BusinessProgramSmallCommContract } from "./bindings/BusinessProgramSmallComm.js";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { Barretenberg } from "@aztec/bb.js";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { SponsoredFPCContract } from "@aztec/noir-contracts.js/SponsoredFPC";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { getContractInstanceFromInstantiationParams } from "@aztec/stdlib/contract";
import { deriveSigningKey } from "@aztec/stdlib/keys";
import { Fr } from "@aztec/aztec.js/fields";

// ─── Config ──────────────────────────────────────────────────────────────────

const DEVNET_NODE_URL = "https://v4-devnet-2.aztec-labs.com";
const DEPLOY_TIMEOUT = 1200000; // 20 min
const TX_TIMEOUT = 300000; // 5 min

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/attestation_data_grumpkin_small.json";
const GRUMPKIN_BATCH_SIZE = 253;

// Generator point H for Pedersen commitments
const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function getSponsoredFPCInstance() {
  return getContractInstanceFromInstantiationParams(SponsoredFPCContract.artifact, {
    salt: new Fr(0n),
  });
}

async function setupWallet() {
  const node = createAztecNodeClient(DEVNET_NODE_URL);
  return EmbeddedWallet.create(node, { ephemeral: true, pxeConfig: { proverEnabled: true } });
}

async function deployAccount(wallet: EmbeddedWallet) {
  const secretKey = Fr.random();
  const salt = Fr.random();
  const signingKey = deriveSigningKey(secretKey);

  console.log(`🔑 Secret key: ${secretKey}`);
  console.log(`🧂 Salt: ${salt}`);
  console.log("⚠️  Save these if you want to reuse this account!");

  const account = await wallet.createSchnorrAccount(secretKey, salt, signingKey);
  console.log(`Account address: ${account.address}`);

  const sponsoredFPC = await getSponsoredFPCInstance();
  await wallet.registerContract(sponsoredFPC, SponsoredFPCContract.artifact);
  const paymentMethod = new SponsoredFeePaymentMethod(sponsoredFPC.address);

  const deployMethod = await account.getDeployMethod();
  console.log("⏳ Deploying account on-chain (~2-5 min)...");
  await deployMethod.send({
    from: AztecAddress.ZERO,
    fee: { paymentMethod },
    skipClassPublication: true,
    skipInstancePublication: true,
    wait: { timeout: 120 },
  });
  console.log("✅ Account deployed!");
  return { account, paymentMethod };
}

// ─── Main ────────────────────────────────────────────────────────────────────

console.log("=".repeat(70));
console.log("TEST 1b: verify_comm — BusinessProgramSmallComm (MAX_COMMS=1)");
console.log("=".repeat(70));

const bb = await Barretenberg.new();
const wallet = await setupWallet();
const { account, paymentMethod } = await deployAccount(wallet);

// Parse attestation data
const rawData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseAttestationData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});
console.log(`\nCommitments in test data: ${parsed.commitments.length}`);

const hashedUrls = await hashUrlsWithPoseidon2(bb, parsed.allowedUrls);

// Deploy contract
console.log("\nDeploying BusinessProgramSmallComm contract...");
const contract = await BusinessProgramSmallCommContract.deploy(wallet, account.address, hashedUrls, H)
  .send({ from: account.address, fee: { paymentMethod }, wait: { timeout: DEPLOY_TIMEOUT } });
console.log("Contract deployed at:", contract.address.toString());

// Profile first
console.log("\nProfiling verify_comm (small)...");
const profile = await contract.methods.verify_comm(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.commitments, parsed.randomScalars,
  parsed.msgsChunks, parsed.msgs, H, parsed.id,
).profile({ from: account.address, profileMode: "full", skipProofGeneration: true });

for (const s of profile.executionSteps) {
  console.log(`  ${s.functionName}: ${s.gateCount?.toLocaleString()} gates`);
}

// Execute on-chain
console.log("\n⏳ Executing verify_comm (small) on-chain...");
const start = Date.now();
const result = await contract.methods.verify_comm(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.commitments, parsed.randomScalars,
  parsed.msgsChunks, parsed.msgs, H, parsed.id,
).send({ from: account.address, fee: { paymentMethod }, wait: { timeout: TX_TIMEOUT } });

console.log(`\n✅ Transaction confirmed!`);
console.log(`   Status:       ${result.status}`);
console.log(`   Block number: ${result.blockNumber}`);
console.log(`   Duration:     ${((Date.now() - start) / 1000).toFixed(1)}s`);

await bb.destroy();
process.exit(0);
