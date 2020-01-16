# Substrate DID Pallet

The DID pallet provides functionality for DIDs management. It uses a universal identity registry where all the required data is associated with an address. It enables the possibility to create a portable, persistent,  privacy-protecting, and personal identity.

## Self-Sovereign Identity

A decentralized identity or self-sovereign identity is a new approach where no one but you own or control the state of your digital identity.

Some of the inherited benefits of self-sovereign identity are:

* Seamless Identity Verification
* Non-Custodial Login Solutions
* Stronger Protections for Critical Infrastructure
* Securing the Internet of Things

## DID

_Decentralized identifiers (DIDs) are a new type of identifier to provide verifiable, decentralized digital identity. These new identifiers are designed to enable the controller of a DID to prove control over it and to be implemented __independently__ of any __centralized registry, identity provider, or certificate authority__. DIDs are URLs that relate a DID subject to a DID document allowing trustable interactions with that subject. DID documents are simple documents describing how to use that specific DID. Each DID document can express cryptographic material, verification methods, or service endpoints, which provide a set of mechanisms enabling a DID controller to prove control of the DID. Service endpoints enable trusted interactions with the DID subject._  - [DID - W3C Community Contributor](https://w3c-ccg.github.io/did-spec/)

## DID Document

_A set of data that describes the subject of a DID, including mechanisms, such as public keys and pseudonymous biometrics, that the DID subject can use to authenticate itself and prove their association with the DID. A DID Document may also contain other attributes or claims describing the subject. These documents are graph-based data structures that are typically expressed using JSON-LD, but may be expressed using other compatible graph-based data formats._ [DID - Documents](https://w3c-ccg.github.io/did-spec/#dfn-did-document)

**To create a DID-Document, a *DID resolver* needs to get all the information from the registry and validate the credentials.** _DID resolvers are a separate component in the DID stack._

## DID document examples for compatibility between different projects

### Substrate

```JSON
{  
   "@context":"https://w3id.org/did/v1",
   "id":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX",
   "publicKeys":[  
      {  
         "id":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#owner",
         "owner":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX",
         "type":"Secp256k1VerificationKey2018",
         "publicKeyHex":"e43a60dbfc251a3a835b45b172bcb49243ed56f820ca89a1c746143c1ab9565d",
         "address":"5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX"
      },
      {  
         "id":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#signingKey#delegate-1",
         "type":"Sr25519VerificationKey2018",
         "publicKeyHex":"dea36bf1a0c198afd259633c2e70b502b19577cc5133760ac569ea6fb4d3b977",
         "address":"5H6d2vR8iqQRANBe7bNegFbEiEJgeCKid4VhS3Pg52VUEqeM"
      },
      {
         "id": "did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#delegate-2",
         "type": "RSAVerificationKey2018",
         "owner": "did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX",
         "publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
      }
   ],
   "service": [
      {
         "id": "did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#openid",
         "serviceEndpoint":"https://openid.example.com/",
         "type":"OpenIdConnectVersion1.0Service"
      }
   ],
   "authentication":[
      {  
         "type":"Secp256k1SignatureAuthentication2018",
         "publicKey":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#owner",
      }
   ],
   "updated":"2019-06-03T06:41:39.723Z"
}
```

### uPort

```JSON
{  
   "@context":"https://w3id.org/did/v1",
   "id":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
   "publicKey":[  
      {  
         "id":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#owner",
         "type":"Secp256k1VerificationKey2018",
         "owner":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
         "ethereumAddress":"0xb9c5714089478a327f09197987f16f9e5d936e8a"
      }
   ],
   "authentication":[  
      {  
         "type":"Secp256k1SignatureAuthentication2018",
         "publicKey":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#owner"
      }
   ]
}
```

### 3Box

```JSON
{  
   "@context":"https://w3id.org/did/v1",
   "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf",
   "publicKeys":[  
      {  
         "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#signingKey",
         "type":"Secp256k1VerificationKey2018",
         "publicKeyHex":"03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
      },
      {  
         "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#encryptionKey",
         "type":"Curve25519EncryptionPublicKey",
         "publicKeyBase64":"AtF8hCxh9h1zlExuOZutuw+tRzmk3zVdfA=="
      },
      {  
         "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#managementKey",
         "type":"Secp256k1VerificationKey2018",
         "ethereumAddress":"0xb9c5714089478a327f09197987f16f9e5d936e8a"
      }
   ],
   "authentication":[  
      {  
         "type":"Secp256k1SignatureAuthentication2018",
         "publicKey":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#signingKey"
      }
   ]
}
```

## Registry Test

Execute module tests

```bash
cargo test -p pallet-did
```

## About This Pallet

[TODO]