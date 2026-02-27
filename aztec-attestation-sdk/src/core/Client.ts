import { createAztecNodeClient } from "@aztec/aztec.js/node";
import type { AztecNode } from "@aztec/aztec.js/node";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { getPXEConfig } from "@aztec/pxe/server";
import { EmbeddedWallet } from '@aztec/wallets/embedded';
import { rm } from "node:fs/promises";
import { Barretenberg } from "@aztec/bb.js";
import { hashUrlsWithPoseidon2, parseAllowedUrls } from "att-verifier-parsing";
import { SponsoredFeePaymentMethod } from "@aztec/aztec.js/fee";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { Fr, GrumpkinScalar } from "@aztec/aztec.js/fields";
import {
  getContractInstanceFromInstantiationParams,
  type ContractInstanceWithAddress,
} from '@aztec/aztec.js/contracts';
import type { AccountManager } from '@aztec/aztec.js/wallet';
import { SponsoredFPCContract, SponsoredFPCContractArtifact } from '@aztec/noir-contracts.js/SponsoredFPC';
import { SPONSORED_FPC_SALT } from '@aztec/constants';
export type NetworkMode = "local" | "devnet";

export interface ClientConfig {
  nodeUrl: string;
  pxeDataDirectory?: string;
  proverEnabled?: boolean;
  cleanupBeforeInit?: boolean;
  mode?: NetworkMode;
}

// Helper function from Aztec Starter https://github.com/AztecProtocol/aztec-starter/blob/v4.0.0-devnet.2-patch.1/src/utils/sponsored_fpc.ts
async function getSponsoredFPCInstance(): Promise<ContractInstanceWithAddress> {
  return await getContractInstanceFromInstantiationParams(SponsoredFPCContractArtifact, {
    salt: new Fr(SPONSORED_FPC_SALT),
  });
}

/**
 * Core Aztec client for PXE, wallet, and bb.
 * Supports both local sandbox and devnet modes.
 */
export class Client {
  private node: AztecNode;
  private wallet?: EmbeddedWallet;
  private bb?: Barretenberg;
  private config: Required<ClientConfig>;
  private sponsoredFPC?: any;
  private sponsoredPaymentMethod?: SponsoredFeePaymentMethod;

  constructor(config: ClientConfig) {
    this.node = createAztecNodeClient(config.nodeUrl);
    this.config = {
      nodeUrl: config.nodeUrl,
      pxeDataDirectory: config.pxeDataDirectory || "pxe",
      proverEnabled: config.proverEnabled ?? true,
      cleanupBeforeInit: config.cleanupBeforeInit ?? true,
      mode: config.mode || "local"
    };
  }

  private ensureInitialized(): void {
    if (!this.wallet || !this.bb) {
      throw new Error("Client not initialized. Call initialize() first.");
    }
  }

  /**
   * Sets up PXE, wallet, and Barretenberg instances.
   * For devnet mode, also sets up sponsored FPC for fee payment.
   */
  async initialize(): Promise<void> {
    if (this.config.mode === "local") {
      const pxeConfig = getPXEConfig();

      if (this.config.cleanupBeforeInit) {
        await rm(this.config.pxeDataDirectory, { recursive: true, force: true });
      }

      pxeConfig.dataDirectory = this.config.pxeDataDirectory;
      pxeConfig.proverEnabled = this.config.proverEnabled;

      // this.wallet = await EmbeddedWallet.create(this.node, pxeConfig);
      this.wallet = await EmbeddedWallet.create(this.node, { pxeConfig: pxeConfig });
    } else {
      // Devnet mode
      // this.wallet = await EmbeddedWallet.create(this.node, { proverEnabled: this.config.proverEnabled });
      this.wallet = await EmbeddedWallet.create(this.node, { pxeConfig: { proverEnabled: this.config.proverEnabled }} );

      // Setup sponsored FPC for devnet
      const SPONSORED_FPC_SALT = new Fr(0n);
      // this.sponsoredFPC = await getContractInstanceFromInstantiationParams(SponsoredFPCContract.artifact, {
      //   salt: SPONSORED_FPC_SALT,
      // });
      this.sponsoredFPC = await getSponsoredFPCInstance();

      await this.wallet.registerContract(this.sponsoredFPC, SponsoredFPCContract.artifact);

      this.sponsoredPaymentMethod = new SponsoredFeePaymentMethod(this.sponsoredFPC.address);
    }

    this.bb = await Barretenberg.new();
  }

  /**
   * Retrieves a test account by index (0-2) for local mode.
   * For devnet mode, deploys a new Schnorr account.
   */
  async getAccount(index: number = 0) {
    this.ensureInitialized();

    if (this.config.mode === "local") {
      const accountsData = await getInitialTestAccountsData();

      if (index < 0 || index >= accountsData.length) {
        throw new Error(`Account index ${index} out of range. Available: 0-${accountsData.length - 1}`);
      }

      const accountData = accountsData[index];
      return await this.wallet!.createSchnorrAccount(
        accountData.secret,
        accountData.salt
      );
    } else {
      // Devnet mode - deploy new account
      return await this.deployDevnetAccount();
    }
  }

  /**
   * Deploys a new Schnorr account on devnet with sponsored FPC.
   * This takes ~2-5 minutes on devnet.
   */
  private async deployDevnetAccount() {
    console.log('Deploying Schnorr account on devnet...');

    const secretKey = Fr.random();
    const signingKey = GrumpkinScalar.random();
    const salt = Fr.random();

    console.log(`🔑 Secret key: ${secretKey.toString()}`);
    console.log(`🖊️  Signing key: ${signingKey.toString()}`);
    console.log(`🧂 Salt: ${salt.toString()}`);
    console.log('⚠️  Save these keys if you want to reuse this account!');

    const account = await this.wallet!.createSchnorrAccount(secretKey, salt, signingKey);
    console.log(`Account address: ${account.address}`);

    const deployMethod = await account.getDeployMethod();

    console.log('Deploying account on-chain (this takes ~2-5 minutes)...');
    const receipt = await deployMethod.send({
      from: AztecAddress.ZERO,
      fee: { paymentMethod: this.sponsoredPaymentMethod! },
      wait: { timeout: 120000, returnReceipt: true }
    });

    console.log(`Account deployed! TX: ${receipt.txHash}`);
    return account;
  }

  /**
   * Retrieves multiple test accounts (local mode only).
   * For devnet, use getAccount() to deploy accounts one at a time.
   */
  async getAccounts(count: number) {
    if (this.config.mode === "devnet") {
      throw new Error("getAccounts() not supported in devnet mode. Use getAccount() to deploy individual accounts.");
    }

    const accounts: AccountManager[] = [];
    for (let i = 0; i < count; i++) {
      accounts.push(await this.getAccount(i));
    }
    return accounts;
  }

  /**
   * Hashes URLs with Poseidon2 for contract storage.
   */
  async hashUrls(urls: string[]): Promise<bigint[]> {
    this.ensureInitialized();
    const urlsAsBytes = parseAllowedUrls(urls);
    return await hashUrlsWithPoseidon2(this.bb!, urlsAsBytes);
  }

  /**
   * Returns the payment method for transactions.
   * On devnet, this is the sponsored FPC. On local, returns undefined.
   */
  getPaymentMethod(): SponsoredFeePaymentMethod | undefined {
    return this.sponsoredPaymentMethod;
  }

  /**
   * Returns true if running in devnet mode.
   */
  isDevnet(): boolean {
    return this.config.mode === "devnet";
  }

  getNode(): AztecNode {
    return this.node;
  }

  getWallet(): EmbeddedWallet {
    this.ensureInitialized();
    return this.wallet!;
  }

  getBarretenberg(): Barretenberg {
    this.ensureInitialized();
    return this.bb!;
  }

  /**
   * Cleans up Barretenberg instance.
   */
  async cleanup(): Promise<void> {
    if (this.bb) {
      await this.bb.destroy();
      this.bb = undefined;
    }
  }
}
