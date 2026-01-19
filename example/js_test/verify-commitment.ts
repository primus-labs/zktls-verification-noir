import fs from "fs";
import { parseAttestationData } from "att-verifier-parsing";
import { Client, ContractHelpers } from "../../aztec-attestation-sdk/src/index.js";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/attestation_data_grumpkin.json";
const GRUMPKIN_BATCH_SIZE = 253;

const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false
};

console.log("Commitment-based Attestation Verification Example");
console.log("=".repeat(80));

const client = new Client({
  nodeUrl: "http://localhost:8080"
});
await client.initialize();

const alice = await client.getAccount(0);

console.log("\n1. Parsing attestation data...");
const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseAttestationData(attestationData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("2. Deploying contract...");
const contract = await ContractHelpers.deployContract<BusinessProgramContract>(
  BusinessProgramContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ALLOWED_URL,
    pointH: H,
    from: alice.address
  }
);
console.log(`   Contract deployed at: ${contract.address.toString()}`);

console.log("3. Verifying attestation...");
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
).send({ from: alice.address }).wait();

console.log("\n" + "=".repeat(80));
console.log("Result:", result.status);
console.log("Block:", result.blockNumber);

if (result.status === "success") {
  const events = await ContractHelpers.getSuccessEvents(
    client.getNode(),
    BusinessProgramContract.events.SuccessEvent,
    result.blockNumber!,
    2
  );
  console.log("Event emitted:", events.length > 0 ? "OK" : "Not OK");
}

await client.cleanup();
