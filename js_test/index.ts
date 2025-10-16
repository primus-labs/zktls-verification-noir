import { AztecAddress, createPXEClient } from "@aztec/aztec.js";
import { getDeployedTestAccountsWallets } from "@aztec/accounts/testing";
import { BusinessProgramContract } from "./bindings/BusinessProgram.ts"
import { AttVerifierContract } from "./bindings/AttVerifier.ts";
const pxe = await createPXEClient("http://localhost:8080");

const alice = (await getDeployedTestAccountsWallets(pxe))[0];
const bob = (await getDeployedTestAccountsWallets(pxe))[1];

// deploy business program
const businessProgram = await BusinessProgramContract.deploy(alice).send({ from: alice.getAddress() })
    .deployed();;
// test calling verify()
let reuslt = await businessProgram.methods.verify([1, 2, 3]).send({ from: alice.getAddress() })
    .wait();
console.log(reuslt);


// deploy attVerifierContract
const attVerifierContract = await AttVerifierContract.deploy(alice).send({ from: alice.getAddress() })
    .deployed();;
// use the address of businessProgram
let result = await attVerifierContract.methods.decrypt_and_check([1, 2, 3], businessProgram.address).send({ from: alice.getAddress() }).wait();
console.log(result);


