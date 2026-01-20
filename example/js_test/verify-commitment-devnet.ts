import fs from "fs";
import { parseAttestationData, Client, ContractHelpers } from "aztec-attestation-sdk";
import { BusinessProgramSmallCommContract } from "./bindings/BusinessProgramSmallComm.js";

/**
 * Example: Verify commitment-based attestation on DEVNET
 */

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/attestation_data_grumpkin_small.json";
const GRUMPKIN_BATCH_SIZE = 253;
const DEPLOY_TIMEOUT = 1200000; // 20 minutes
const TX_TIMEOUT = 180000;      // 3 minutes

const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false
};

console.log("Commitment-based Attestation Verification - DEVNET");
console.log("=".repeat(80));

// Initialize client for DEVNET mode
const client = new Client({
  nodeUrl: "https://next.devnet.aztec-labs.com",
  mode: "devnet"
});
await client.initialize();

// Deploy account on devnet (this takes ~2-5 minutes)
const alice = await client.getAccount();

console.log("\n1. Parsing attestation data...");
const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseAttestationData(attestationData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("2. Deploying contract (this may take up to 20 minutes on devnet)...");
const contract = await ContractHelpers.deployContract<BusinessProgramSmallCommContract>(
  BusinessProgramSmallCommContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ALLOWED_URL,
    pointH: H,
    from: alice.address,
    timeout: DEPLOY_TIMEOUT
  }
);
console.log(`   Contract deployed at: ${contract.address.toString()}`);

console.log("3. Verifying attestation...");
// For devnet, we need to add fee payment
const paymentMethod = client.getPaymentMethod();
const sendOptions: any = { from: alice.address };
if (paymentMethod) {
  sendOptions.fee = { paymentMethod };
}

const result = await contract.methods.verify_comm(
  parsed.publicKeyX,
  parsed.publicKeyY,
  parsed.hash,
  parsed.signature,
  parsed.requestUrls,
  parsed.allowedUrls,
  parsed.commitments,
  parsed.randomScalars,
  parsed.msgsChunks,
  parsed.msgs,
  H,
  parsed.id
).send(sendOptions).wait({ timeout: TX_TIMEOUT });

console.log("\n" + "=".repeat(80));
console.log("Result:", result.status);
console.log("Block:", result.blockNumber);

if (result.status === "success") {
  const events = await ContractHelpers.getSuccessEvents(
    client.getNode(),
    BusinessProgramSmallCommContract.events.SuccessEvent,
    result.blockNumber!,
    2
  );
  console.log("Event emitted:", events.length > 0 ? "OK" : "Not OK");
}

await client.cleanup();
process.exit(0);