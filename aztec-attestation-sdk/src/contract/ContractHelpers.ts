import type { AztecAddress } from "@aztec/aztec.js/addresses";
import type { AztecNode } from "@aztec/aztec.js/node";
import { getDecodedPublicEvents } from "@aztec/aztec.js/events";
import type { Client } from "../core/Client.js";

/**
 * Embedded curve point for Pedersen commitments.
 */
export interface EmbeddedCurvePoint {
  x: bigint;
  y: bigint;
  is_infinite: boolean;
}

/**
 * Deployment parameters for attestation verifier contracts.
 */
export interface ContractDeploymentParams {
  admin: AztecAddress;
  allowedUrls: string[];
  pointH?: EmbeddedCurvePoint;
  from: AztecAddress;
  timeout?: number;
}

/**
 * Event emitted upon successful attestation verification.
 */
export interface SuccessEvent {
  sender: AztecAddress;
  contract_address: AztecAddress;
  id: bigint;
}

/**
 * Helpers for attestation verifier contracts.
 */
export class ContractHelpers {
  /**
   * Deploys an attestation verifier contract with hashed URLs.
   * Automatically handles fee payment for devnet mode.
   */
  static async deployContract<T>(
    contractClass: any,
    client: Client,
    params: ContractDeploymentParams
  ): Promise<T> {
    const wallet = client.getWallet();
    const hashedUrls = await client.hashUrls(params.allowedUrls);

    const deploymentArgs = params.pointH
      ? [params.admin, hashedUrls, params.pointH]
      : [params.admin, hashedUrls];

    const sendOptions: any = { from: params.from };

    // Add fee payment for devnet
    if (client.isDevnet()) {
      const paymentMethod = client.getPaymentMethod();
      if (paymentMethod) {
        sendOptions.fee = { paymentMethod };
      }
    }

    const deployment = contractClass
      .deploy(wallet, ...deploymentArgs)
      .send(sendOptions);

    // Add timeout if specified
    if (params.timeout) {
      return await deployment.deployed({ timeout: params.timeout });
    }

    return await deployment.deployed();
  }

  /**
   * Retrieves SuccessEvent instances from a specific block.
   */
  static async getSuccessEvents(
    node: AztecNode,
    eventType: any,
    blockNumber: number,
    maxLookback: number = 2
  ): Promise<SuccessEvent[]> {
    try {
      return await getDecodedPublicEvents(node, eventType, blockNumber, maxLookback);
    } catch (error) {
      console.error("Error fetching success events:", error);
      return [];
    }
  }
}
