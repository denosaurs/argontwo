# argontwo

[![Tags](https://img.shields.io/github/release/denosaurs/argontwo)](https://github.com/denosaurs/argontwo/releases)
[![deno doc](https://doc.deno.land/badge.svg)](https://doc.deno.land/https/deno.land/x/argontwo/mod.ts)
[![checks](https://github.com/denosaurs/argontwo/actions/workflows/checks.yml/badge.svg)](https://github.com/denosaurs/argontwo/actions/workflows/checks.yml)
[![License](https://img.shields.io/github/license/denosaurs/argontwo)](https://github.com/denosaurs/argontwo/blob/master/LICENSE)
[![Dependencies](https://img.shields.io/endpoint?url=https%3A%2F%2Fdeno-visualizer.danopia.net%2Fshields%2Fdep-count%2Fhttps%2Fdeno.land%2Fx%2Fargontwo%2Fmod.ts)](https://deno-visualizer.danopia.net/dependencies-of/https/deno.land/x/argontwo/mod.ts)
[![Dependency freshness](https://img.shields.io/endpoint?url=https%3A%2F%2Fdeno-visualizer.danopia.net%2Fshields%2Fupdates%2Fhttps%2Fdeno.land%2Fx%2Fargontwo%2Fmod.ts)](https://deno-visualizer.danopia.net/dependencies-of/https/deno.land/x/argontwo/mod.ts)

This module provides [Argon2](https://en.wikipedia.org/wiki/Argon2) hashing
support for deno and the web by providing [simple bindings](src/lib.rs) using
[argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
compiled to webassembly.

## Usage

```ts
import { hash } from "https://deno.land/x/argontwo/mod.ts";

const encoder = new TextEncoder();

const password = encoder.encode("password");
const salt = encoder.encode("somesalt");

console.log(hash(password, salt));

// Should log:
// Uint8Array(32) [
//   168, 185, 165, 229, 198, 234,  20,  3,
//   186,  99,  21,  71, 134, 180, 129, 28,
//   253,  20,  89, 220, 107,  35,  25, 13,
//   112, 207,  26,  49, 125, 219, 151, 53
// ]
```

## Maintainers

- Elias Sjögreen ([@eliassjogreen](https://github.com/eliassjogreen))

## Other

### Contribution

Pull request, issues and feedback are very welcome. Code style is formatted with
`deno fmt` and commit messages are done following
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) spec.

### Licence

Copyright 2021, the denosaurs team. All rights reserved. MIT license.
