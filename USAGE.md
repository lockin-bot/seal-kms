# Seal KMS Usage Guide for Client Enclaves

This guide explains how client enclaves can request and receive encrypted private keys from the Seal KMS service.

## Overview

The Seal KMS service provides deterministic private key derivation for authorized enclaves. Each enclave type receives a unique private key derived from the master key, ensuring consistent key generation across requests.

## Prerequisites

1. Your enclave must be registered on the Sui blockchain with a valid enclave configuration object
2. Your enclave must be able to generate attestation documents containing your Ed25519 public key
3. Your enclave must have an Ed25519 key pair for signing intents (this is the key in your attestation)

## Request Flow

### 1. Generate Ephemeral ECDH Key Pair for Encryption

Generate a separate ephemeral ECDH key pair (using prime256v1/secp256r1 curve) specifically for encrypting the response. This is NOT the same as your Ed25519 signing key:

```typescript
const ecdh = crypto.createECDH('prime256v1');
const ephemeralPublicKey = ecdh.generateKeys();
const ephemeralPrivateKey = ecdh.getPrivateKey();
```

### 2. Create and Sign Intent

Create an intent for the key request and sign it with your enclave's Ed25519 private key (the one whose public key is in your attestation document). The ephemeral public key MUST be included in the intent to bind it to your request:

```typescript
const ENCLAVE_KEY_REQUEST_INTENT = 2;
const timestamp = Date.now();

const intent = bcs
  .struct('Intent', {
    intent: bcs.u8(),
    timestamp_ms: bcs.u64(),
    data: bcs.struct('EnclaveKeyRequest', {
      config_object_id: bcs.byteVector(),
      ephemeral_public_key: bcs.byteVector(),
    }),
  })
  .serialize({
    intent: ENCLAVE_KEY_REQUEST_INTENT,
    timestamp_ms: timestamp,
    data: {
      config_object_id: toHex(enclaveConfigObjectId),
      ephemeral_public_key: ephemeralPublicKey, // From step 1
    },
  });

const signature = ed25519Sign(intent.toBytes(), enclavePrivateKey);
```

### 3. Prepare Request

```typescript
interface EnclaveKeyRequest {
  ephemeral_public_key: string; // hex encoded ECDH public key (from step 1)
  attestation_document: string; // hex encoded attestation (contains Ed25519 public key)
  enclave_config_object_id: string; // Your enclave's config object ID on Sui
  timestamp_ms: number; // Current timestamp in milliseconds (same as in intent)
  signature: string; // hex encoded Ed25519 signature of the intent (from step 2)
}
```

Note: The server will reconstruct the intent from these fields to verify the signature.

### 4. Send Request

Send a POST request to the Seal KMS endpoint:

```typescript
const response = await fetch('http://<seal-kms-endpoint>/enclave-key', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(request),
});
```

### 5. Process Response

The response contains the encrypted private key and metadata:

```typescript
interface EnclaveKeyResponse {
  encrypted_private_key: string; // hex encoded encrypted key
  iv: string; // hex encoded initialization vector
  auth_tag: string; // hex encoded authentication tag
  server_public_key: string; // hex encoded server's ephemeral public key
  derived_for: string; // Enclave type the key was derived for
  timestamp_ms: number; // Response timestamp
  signature: string; // hex encoded signature from Seal KMS
  enclave_object_id: string; // Seal KMS enclave object ID for validation
}
```

### 6. Verify Response Signature

Verify the response was signed by the authentic Seal KMS enclave:

```typescript
const ENCLAVE_KEY_RESPONSE_INTENT = 3;

// Reconstruct the intent that was signed
const responseIntent = bcs
  .struct('Intent', {
    intent: bcs.u8(),
    timestamp_ms: bcs.u64(),
    data: bcs.struct('EnclaveKeyResponse', {
      encrypted_private_key: bcs.byteVector(),
      iv: bcs.byteVector(),
      auth_tag: bcs.byteVector(),
      server_public_key: bcs.byteVector(),
      derived_for: bcs.string(),
    }),
  })
  .serialize({
    intent: ENCLAVE_KEY_RESPONSE_INTENT,
    timestamp_ms: response.timestamp_ms,
    data: {
      encrypted_private_key: toHex(response.encrypted_private_key),
      iv: toHex(response.iv),
      auth_tag: toHex(response.auth_tag),
      server_public_key: toHex(response.server_public_key),
      derived_for: response.derived_for,
    },
  });

// Fetch the Seal KMS enclave's public key from Sui blockchain
const sealEnclavePublicKey = await fetchEnclavePublicKey(response.enclave_object_id);

// Verify signature
const isValid = ed25519Verify(
  responseIntent.toBytes(),
  toHex(response.signature),
  sealEnclavePublicKey
);
```

### 7. Decrypt the Private Key

Use your ephemeral ECDH private key (from step 1) to compute the shared secret and decrypt:

```typescript
// Compute shared secret using your ephemeral ECDH private key and server's public key
const ecdh = crypto.createECDH('prime256v1');
ecdh.setPrivateKey(ephemeralPrivateKey); // From step 1
const sharedSecret = ecdh.computeSecret(
  toHex(response.server_public_key)
);

// Derive encryption key using HKDF (same parameters as server)
const encryptionKey = crypto.hkdfSync(
  'sha256',
  sharedSecret,
  Buffer.from('encryption'),
  Buffer.from('seal-kms'),
  32
);

// Decrypt using AES-256-GCM
const decipher = crypto.createDecipheriv(
  'aes-256-gcm',
  encryptionKey,
  toHex(response.iv)
);
decipher.setAuthTag(toHex(response.auth_tag));

const decryptedKey = Buffer.concat([
  decipher.update(toHex(response.encrypted_private_key)),
  decipher.final(),
]);
```

## Security Considerations

1. **Key Separation**: Keep your Ed25519 signing keys and ECDH encryption keys separate
2. **Ephemeral Key Binding**: The ephemeral public key is included in the signed intent, ensuring only the requester can decrypt the response
3. **Timestamp Validation**: Requests must include a timestamp within 5 minutes of the current time
4. **Attestation Verification**: The Seal KMS validates your enclave's attestation against the registered configuration
5. **Intent Signatures**: Both request and response use signed intents (Ed25519) to ensure authenticity
6. **Ephemeral Keys**: Use fresh ephemeral ECDH keys for each request to ensure forward secrecy
7. **Enclave Authorization**: The Seal KMS may implement additional authorization checks based on enclave type

## Key Derivation

The Seal KMS derives keys deterministically using HKDF:
- Each enclave type receives a unique key
- The same enclave type will always receive the same key
- Keys are derived from the master key using the enclave type as context

## Error Handling

Common error responses:

```typescript
{
  "success": false,
  "error": "Error description"
}
```

Possible errors:
- `Request timestamp is too old or too far in the future` - Synchronize your clock
- `Attestation validation failed` - Check your attestation document and enclave configuration
- `Invalid intent signature` - Verify your signing implementation
- `Enclave type not authorized` - Your enclave type may not be authorized
- `Enclave object ID not configured` - The Seal KMS is not properly registered

## Example Implementation

See the test client implementation in `app/test-client.ts` for a complete example of requesting and decrypting a private key.
