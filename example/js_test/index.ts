import fs from "fs";
import { parseAttestationData, hashUrlsWithPoseidon2 } from "att-verifier-parsing";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { TestWallet } from "@aztec/test-wallet/server";
import { getPXEConfig } from "@aztec/pxe/server";
import { BusinessProgramContract, SuccessEvent } from "./bindings/BusinessProgram.js";
import { performance } from "perf_hooks";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { rm } from "node:fs/promises";
import { Barretenberg, Fr } from "@aztec/bb.js";
import { getDecodedPublicEvents } from '@aztec/aztec.js/events';

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/attestation_data_grumpkin.json";
const GRUMPKIN_BATCH_SIZE = 253;

const node = createAztecNodeClient("http://localhost:8080");

const config = getPXEConfig();
await rm("pxe", { recursive: true, force: true });
config.dataDirectory = "pxe";
config.proverEnabled = true;
const wallet = await TestWallet.create(node, config);
const [aliceAccount] = await getInitialTestAccountsData();
let alice = await wallet.createSchnorrAccount(aliceAccount.secret, aliceAccount.salt);

// Load attestation testdata
const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));

// Parse attestation data using the library
const parsed = parseAttestationData(attestationData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

// Hash allowed URLs using Poseidon2
const bb = await Barretenberg.new();
const hashedUrls = await hashUrlsWithPoseidon2(bb, parsed.allowedUrls, Fr);

// Point H for Pedersen commitment
let H = { 
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n, 
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n, 
  is_infinite: false 
};

// Deploy business program contract
const businessProgram = await BusinessProgramContract.deploy(
  wallet, 
  alice.address, 
  hashedUrls, 
  H
)
  .send({ from: aliceAccount.address })
  .deployed();

console.log("Deployed business program");

// Verify attestation
const start = performance.now();

let result = await businessProgram.methods.verify_comm(
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
).send({ from: aliceAccount.address }).wait();

const end = performance.now();
const duration = (end - start).toFixed(2);

console.log(result);
console.log(`Verification call took ${duration} ms`);

if (result.status != "success") {
  console.log("Verification failed");
}

// Get public event
const success_event = await getDecodedPublicEvents<SuccessEvent>(
  node,
  BusinessProgramContract.events.SuccessEvent,
  result.blockNumber!,
  2
);

console.log("Success event: ", success_event);

// Cleanup
await bb.destroy();