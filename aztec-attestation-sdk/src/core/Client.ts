import { createAztecNodeClient } from "@aztec/aztec.js/node";
import type { AztecNode } from "@aztec/aztec.js/node";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { TestWallet } from "@aztec/test-wallet/server";
import { getPXEConfig } from "@aztec/pxe/server";
import { AccountManager } from "@aztec/aztec.js/wallet";
import { rm } from "node:fs/promises";
import { Barretenberg } from "@aztec/bb.js";
import { hashUrlsWithPoseidon2, parseAllowedUrls } from "att-verifier-parsing";

export interface ClientConfig {
  nodeUrl: string;
  pxeDataDirectory?: string;
  proverEnabled?: boolean;
  cleanupBeforeInit?: boolean;
}

/**
 * Core Aztec client for PXE, wallet, and bb.
 */
export class Client {
  private node: AztecNode;
  private wallet?: TestWallet;
  private bb?: Barretenberg;
  private config: Required<ClientConfig>;

  constructor(config: ClientConfig) {
    this.node = createAztecNodeClient(config.nodeUrl);
    this.config = {
      nodeUrl: config.nodeUrl,
      pxeDataDirectory: config.pxeDataDirectory || "pxe",
      proverEnabled: config.proverEnabled ?? true,
      cleanupBeforeInit: config.cleanupBeforeInit ?? true
    };
  }

  private ensureInitialized(): void {
    if (!this.wallet || !this.bb) {
      throw new Error("Client not initialized. Call initialize() first.");
    }
  }

  /**
   * Sets up PXE, wallet, and Barretenberg instances.
   */
  async initialize(): Promise<void> {
    const pxeConfig = getPXEConfig();

    if (this.config.cleanupBeforeInit) {
      await rm(this.config.pxeDataDirectory, { recursive: true, force: true });
    }

    pxeConfig.dataDirectory = this.config.pxeDataDirectory;
    pxeConfig.proverEnabled = this.config.proverEnabled;

    this.wallet = await TestWallet.create(this.node, pxeConfig);
    this.bb = await Barretenberg.new();
  }

  /**
   * Retrieves a test account by index (0-2).
   */
  async getAccount(index: number = 0): Promise<AccountManager> {
    this.ensureInitialized();

    const accountsData = await getInitialTestAccountsData();

    if (index < 0 || index >= accountsData.length) {
      throw new Error(`Account index ${index} out of range. Available: 0-${accountsData.length - 1}`);
    }

    const accountData = accountsData[index];
    return await this.wallet!.createSchnorrAccount(
      accountData.secret,
      accountData.salt
    );
  }

  /**
   * Retrieves multiple test accounts.
   */
  async getAccounts(count: number): Promise<AccountManager[]> {
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

  getNode(): AztecNode {
    return this.node;
  }

  getWallet(): TestWallet {
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
