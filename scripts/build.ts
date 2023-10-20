import { encodeBase64 } from "https://deno.land/std@0.204.0/encoding/base64.ts";
import { compress } from "https://deno.land/x/lz4@v0.1.2/mod.ts";

const name = "argontwo";

await new Deno.Command("cargo", {
  args: ["build", "--release", "--target", "wasm32-unknown-unknown"],
}).spawn().status;

const wasm = await Deno.readFile(
  `./target/wasm32-unknown-unknown/release/${name}.wasm`,
);
const encoded = encodeBase64(compress(wasm));
const js = `// deno-fmt-ignore-file\n// deno-lint-ignore-file
import { decodeBase64 } from "https://deno.land/std@0.204.0/encoding/base64.ts";
import { decompress } from "https://deno.land/x/lz4@v0.1.2/mod.ts";
export const source = decompress(decodeBase64("${encoded}"));`;

await Deno.writeTextFile("wasm/wasm.js", js);
