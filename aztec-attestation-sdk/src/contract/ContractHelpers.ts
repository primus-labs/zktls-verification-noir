import type { AztecAddress } from "@aztec/aztec.js/addresses";
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
 * Helpers for attestation verifier contracts.
 */
export class ContractHelpers {
  /**
   * Deploys an attestation verifier contract.
   * Hashes the allowed URLs internally using the client's Barretenberg instance.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static async deployContract(
    contractClass: any,
    client: Client,
    params: ContractDeploymentParams
  ): Promise<any> {
    const wallet = client.getWallet();
    const hashedUrls = await client.hashUrls(params.allowedUrls);

    const deploymentArgs = params.pointH
      ? [params.admin, hashedUrls, params.pointH]
      : [params.admin, hashedUrls];

    const sendOpts = {
      from: params.from,
      wait: { timeout: params.timeout ?? 300000 },
    };

    const { contract } = await contractClass.deploy(wallet, ...deploymentArgs).send(sendOpts);
    return contract;
  }
}
