import { alloc, hashRaw, memory } from "./wasm/mod.ts";

function transferToWasm(arr: Uint8Array): [number, number] {
  const len = arr.length;
  const ptr = alloc(len);
  new Uint8Array(memory.buffer, ptr, len).set(arr);
  return [ptr, len];
}

/**
 * The three different Argon2 algorithm variants:
 *
 * - **argon2d**: maximizes resistance to GPU cracking attacks
 * - **argon2i**: optimized to resist side-channel attacks
 * - **argon2id**: (default) hybrid version
 */
export const algorithm = {
  argon2d: 0,
  argon2i: 1,
  argon2id: 3,
} as const;

/**
 * The two different versions of the Argon2 algorithm:
 *
 * - **V0x10** - Version 16, performs overwrites internally
 * - **V0x13** - Version 19, performs XOR internally
 */
export const version = {
  V0x10: 0,
  V0x13: 1,
} as const;

/**
 * The Argon2 parameters
 */
export interface Argon2Params {
  /**
   * The secret key
   */
  secret?: Uint8Array;
  /**
   * The associated data
   */
  ad?: Uint8Array;
  /**
   * The Argon2 algorithm, see {@link algorithm}
   */
  algorithm?: typeof algorithm[keyof typeof algorithm];
  /**
   * Number of iterations, between 1 and (2^32)-1.
   */
  timeCost?: number;
  /**
   * Memory size, expressed in kilobytes, between 1 and (2^32)-1.
   */
  memoryCost?: number;
  /**
   * The number of lanes
   */
  lanes?: number;
  /**
   * The length of the output in bytes
   */
  outputLength?: number;
  /**
   *  The Argon2 version, see {@link version}
   */
  version?: typeof version[keyof typeof version];
}

/**
 * Computes a hash for the password, salt and parameters
 */
export function hash(
  password: Uint8Array,
  salt: Uint8Array,
  params?: Argon2Params,
): Uint8Array {
  const secret = params?.secret;
  const ad = params?.ad ?? new Uint8Array();
  const alg = params?.algorithm ?? algorithm.argon2id;
  const timeCost = params?.timeCost ?? 3;
  const memoryCost = params?.memoryCost ?? 4096;
  const lanes = params?.lanes ?? 1;
  const outLen = params?.outputLength ?? 32;
  const ver = params?.version ?? version.V0x13;

  console.log();

  const [pwdPtr, pwdLen] = transferToWasm(password);
  const [saltPtr, saltLen] = transferToWasm(salt);

  let secretPtr = 0;
  let secretLen = 0;
  if (secret !== undefined) {
    [secretPtr, secretLen] = transferToWasm(secret);
  }

  const adLen = ad.length;
  const adPtr = alloc(adLen);
  const adArr = new Uint8Array(memory.buffer, adPtr, adLen);
  adArr.set(ad);

  const outPtr = hashRaw(
    pwdPtr,
    pwdLen,
    saltPtr,
    saltLen,
    secretPtr,
    secretLen,
    adPtr,
    adLen,
    alg,
    timeCost,
    memoryCost,
    lanes,
    outLen,
    ver,
  );

  return new Uint8Array(memory.buffer, outPtr, outLen);
}
