import { createAztecNodeClient } from "@aztec/aztec.js/node";
import type { AztecNode } from "@aztec/aztec.js/node";
import { getInitialTestAccountsData } from "@aztec/accounts/testing";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { Barretenberg } from "@aztec/bb.js";
import { hashUrlsWithPoseidon2, parseAllowedUrls } from "att-verifier-parsing";
import type { AccountManager } from "@aztec/aztec.js/wallet";

export interface ClientConfig {
  nodeUrl: string;
}

/**
 * Core Aztec client for PXE, wallet, and Barretenberg.
 * Targets local network (`aztec start --local-network`).
 */
export class Client {
  private nodeUrl: string;
  private node: AztecNode;
  private wallet?: EmbeddedWallet;
  private bb?: Barretenberg;

  constructor(config: ClientConfig) {
    this.nodeUrl = config.nodeUrl;
    this.node = createAztecNodeClient(config.nodeUrl);
  }

  private ensureInitialized(): void {
    if (!this.wallet || !this.bb) {
      throw new Error("Client not initialized. Call initialize() first.");
    }
  }

  /**
   * Sets up the embedded PXE, wallet, and Barretenberg instances.
   */
  async initialize(): Promise<void> {
    this.wallet = await EmbeddedWallet.create(this.nodeUrl, { ephemeral: true });
    this.bb = await Barretenberg.new();
  }

  /**
   * Returns a pre-funded local test account by index (0-based).
   */
  async getAccount(index: number = 0): Promise<AccountManager> {
    this.ensureInitialized();
    const accountsData = await getInitialTestAccountsData();
    if (index < 0 || index >= accountsData.length) {
      throw new Error(`Account index ${index} out of range. Available: 0-${accountsData.length - 1}`);
    }
    const accountData = accountsData[index];
    return await this.wallet!.createSchnorrAccount(accountData.secret, accountData.salt);
  }

  /**
   * Returns multiple local test accounts.
   */
  async getAccounts(count: number): Promise<AccountManager[]> {
    const accounts: AccountManager[] = [];
    for (let i = 0; i < count; i++) {
      accounts.push(await this.getAccount(i));
    }
    return accounts;
  }

  /**
   * Hashes URL strings with Poseidon2 for contract initialization.
   */
  async hashUrls(urls: string[]): Promise<bigint[]> {
    this.ensureInitialized();
    const urlsAsBytes = parseAllowedUrls(urls);
    return await hashUrlsWithPoseidon2(this.bb!, urlsAsBytes);
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
   * Destroys the Barretenberg instance. Call before process exit.
   */
  async cleanup(): Promise<void> {
    if (this.bb) {
      await this.bb.destroy();
      this.bb = undefined;
    }
  }
}
