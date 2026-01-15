export { Client } from "./core/Client.js";
export type { ClientConfig } from "./core/Client.js";

export { ContractHelpers } from "./template/ContractHelpers.js";
export type {
  TemplateDeploymentParams,
  EmbeddedCurvePoint,
  SuccessEvent
} from "./template/ContractHelpers.js";

export {
  parseAttestationData,
  parseHashingData,
  hashUrlsWithPoseidon2
} from "att-verifier-parsing";

export type {
  ParsedAttestationData,
  ParsedHashingData,
  ParseConfig,
  AttestationFile
} from "att-verifier-parsing";
