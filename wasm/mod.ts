import { source } from "./wasm.js";

const { instance } = await WebAssembly.instantiate(source, {
  env: {
    panic: (ptr: number, len: number) => {
      const msg = new TextDecoder().decode(
        new Uint8Array(memory.buffer, ptr, len),
      );
      throw new Error(msg);
    },
  },
});

export const memory = instance.exports.memory as WebAssembly.Memory;
export const alloc = instance.exports.alloc as (size: number) => number;
export const dealloc = instance.exports.dealloc as (
  ptr: number,
  size: number,
) => void;

export const hashRaw = instance.exports.hash_raw as (
  pwdPtr: number,
  pwdLen: number,
  saltPtr: number,
  saltLen: number,
  secretPtr: number,
  secretLen: number,
  adPtr: number,
  adLen: number,
  alg: number,
  tCost: number,
  mCost: number,
  lanes: number,
  outLen: number,
  version: number,
) => number;
