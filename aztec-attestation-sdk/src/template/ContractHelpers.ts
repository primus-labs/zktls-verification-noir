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
 * Deployment parameters for contract_template based contracts.
 */
export interface TemplateDeploymentParams {
  admin: AztecAddress;
  allowedUrls: string[];
  pointH?: EmbeddedCurvePoint;
  from: AztecAddress;
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
 * Helpers for contracts based on contract_template.
 */
export class ContractHelpers {
  /**
   * Deploys a contract_template based contract with hashed URLs.
   */
  static async deployContract<T>(
    contractClass: any,
    client: Client,
    params: TemplateDeploymentParams
  ): Promise<T> {
    const wallet = client.getWallet();
    const hashedUrls = await client.hashUrls(params.allowedUrls);

    const deploymentArgs = params.pointH
      ? [params.admin, hashedUrls, params.pointH]
      : [params.admin, hashedUrls];

    return await contractClass
      .deploy(wallet, ...deploymentArgs)
      .send({ from: params.from })
      .deployed();
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
