import { source } from "./wasm.js";

const { instance } = await WebAssembly.instantiate(source, {
  env: {
    panic: (ptr: number, len: number) => {
      const msg = new TextDecoder().decode(
        new Uint8Array(memory.buffer, ptr, len),
      );
      dealloc(ptr, len);
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

export const hash = instance.exports.hash as (
  passwordPtr: number,
  passwordLen: number,
  saltPtr: number,
  saltLen: number,
  secretPtr: number,
  secretLen: number,
  outputPtr: number,
  outputLen: number,
  algorithm: number,
  version: number,
  mCost: number,
  tCost: number,
  pCost: number,
) => void;
