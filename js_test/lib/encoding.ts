import { keccak_256 } from "@noble/hashes/sha3";

export function padTo(arr: number[], target: number): number[] {
  if (arr.length > target) throw new Error(`too long: ${arr.length} > ${target}`);
  return arr.concat(Array(target - arr.length).fill(0));
}

// Solidity-style abi.encodePacked
export function encodePacked(publicData: any): number[] {
  const out: number[] = [];

  // recipient address
  out.push(...Buffer.from(publicData.recipient.slice(2), "hex"));

  // request.hash()
  const req = publicData.request;
  out.push(...keccak_256(Buffer.from(req.url + req.header + req.method + req.body, "utf8")));

  // responseResolve
  if (publicData.reponseResolve.length === 1) {
    const rr = publicData.reponseResolve[0];
    out.push(...keccak_256(Buffer.from(rr.keyName + rr.parseType + rr.parsePath, "utf8")));
  } else {
    const vec = publicData.reponseResolve
      .map((rr: any) => rr.keyName + rr.parseType + rr.parsePath)
      .join("");
    out.push(...keccak_256(Buffer.from(vec, "utf8")));
  }

  out.push(...Buffer.from(publicData.data, "utf8"));
  out.push(...Buffer.from(publicData.attConditions, "utf8"));

  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(publicData.timestamp));
  out.push(...buf);

  out.push(...Buffer.from(publicData.additionParams, "utf8"));

  return out;
}
