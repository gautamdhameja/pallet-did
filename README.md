# DID

_Decentralized Identifiers (DIDs) are a new type of identifier for verifiable, "self-sovereign" digital identity. DIDs are fully under the control of the DID subject, independent from any centralized registry, identity provider, or certificate authority. DIDs are URLs that relate a DID subject to means for trustable interactions with that subject. DIDs resolve to DID Documents — simple documents that describe how to use that specific DID. Each DID Document may contain at least three things: proof purposes, verification methods, and service endpoints. Proof purposes are combined with verification methods to provide mechanisms for proving things. For example, a DID Document can specify that a particular verification method, such as a cryptographic public key or pseudonymous biometric protocol, can be used to verify a proof that was created for the purpose of authentication. Service endpoints enable trusted interactions with the DID controller._  -  [DID - W3C Community Contributor](https://w3c-ccg.github.io/did-spec/)

## Substrate DID Runtime Module 
![Feature Status: WIP – Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](https://img.shields.io/badge/Status-WIP-yellow.svg)

The DID module provides functionality for DIDs management. It uses a universal identity registry where all the required data is associated with an address. It enables the possibility to create a portable, persistent,  privacy-protecting, and personal identity.

# Test

Execute module tests:

```bash
cargo test -p pallet-did
```
