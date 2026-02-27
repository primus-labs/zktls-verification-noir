import fs from "fs";
import { AttVerifierContract, } from "./bindings/AttVerifier.js";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { TestWallet } from "@aztec/test-wallet/server";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { rm } from "node:fs/promises";
import { Barretenberg, Fr } from "@aztec/bb.js";
import { getPXEConfig } from "@aztec/pxe/server";

const MAX_RESPONSE_NUM = 2;
const AllOWED_URL = ["https://api.binance.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/eth_hash.json";

const node = createAztecNodeClient("http://localhost:8080");
const config = getPXEConfig();
await rm("pxe", { recursive: true, force: true });
config.dataDirectory = "pxe";
config.proverEnabled = true;
const wallet = await TestWallet.create(node, { pxeConfig: config });
const [aliceAccount] = await getInitialTestAccountsData();
let alice = await wallet.createSchnorrAccount(aliceAccount.secret, aliceAccount.salt);

// deploy attVerifierContract
const { contract: attVerifierContract, instance: attVerifierInstance } = await AttVerifierContract.deploy(wallet).send({ from: aliceAccount.address, wait: { returnReceipt: true } });
console.log("deployed attverifier");

// prepare allowed urls
const allowedUrls: (bigint | number)[][] = [];
for (const url of AllOWED_URL) {
    const url_bytes = Array.from(new TextEncoder().encode(url));
    allowedUrls.push(url_bytes)
}
const bb = await Barretenberg.new();
const hashedUrls: bigint[] = [];
for (let url of allowedUrls) {
    url = url.slice();
    // pad with zeros to length 1024
    while (url.length < 1024) {
        url.push(0);
    }

    // inputs in bb.poseidon2Hash is now Uint8Array[]
    const frArray = url.map(b => new Fr(BigInt(b)).toBuffer());
    const hashFr = await bb.poseidon2Hash({ inputs: frArray });
    const hashBigInt = BigInt(Fr.fromBuffer(hashFr.hash).toString());
    hashedUrls.push(hashBigInt);
}

// deploy business program
const { contract: businessProgram, instance: businessProgramInstance } = await BusinessProgramContract.deploy(wallet, alice.address, hashedUrls)
    .send({ from: aliceAccount.address, wait: { returnReceipt: true } }); // testAccount has fee juice and is registered in the deployer_wallet
console.log("deployed business program");


// save contract instance info to a JSON file
const instanceInfos = {
    attVerifierContract: {
        constructorArgs: [],
        salt: attVerifierInstance.salt,
        deployer: attVerifierInstance.deployer,
    },
    businessProgram: {
        constructorArgs: [alice.address, hashedUrls.map((value => `0x${value.toString(16)}`))],
        salt: businessProgramInstance.salt,
        deployer: businessProgramInstance.deployer,
    }
};
const json = JSON.stringify(instanceInfos, null, 2);
fs.writeFileSync("deployed_contract.json", json, "utf-8");
console.log("Saved to eployed_contract.json");
await bb.destroy();