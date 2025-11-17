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

## Certificate Verification

The Seal KMS service includes public key certificates with its responses to prove the authenticity of derived public keys. These certificates allow clients to verify that a public key was indeed derived by the legitimate KMS enclave.

### What is a Public Key Certificate?

A `PublicKeyCertificate` is a signed attestation from the KMS enclave that contains:

```typescript
interface PublicKeyCertificate {
  derived_public_key: string;        // The public key that was derived
  kms_enclave_object_id: string;     // The KMS enclave's object ID on Sui
  kms_enclave_public_key: string;    // The KMS enclave's public key (for verification)
  target_enclave_config_id: string;  // The target enclave's config ID
  enclave_type: string;              // The enclave type the key was derived for
  issued_at_ms: number;              // Timestamp when certificate was created
  signature: string;                 // Ed25519 signature over the certificate data
}
```

### Certificate Verifier Implementation

Below is the complete implementation of the certificate verifier utilities that you can copy into your client application:

```typescript
import { bcs } from '@mysten/bcs';
import { verifyEd25519Signature } from './attestation-validator.js';
import type { PublicKeyCertificate } from './enclave-key-service.js';

// Intent type for public key certificate (must match enclave-key-service.ts)
const PUBLIC_KEY_CERTIFICATE_INTENT = 4;

/**
 * Options for certificate verification
 */
export interface VerifyCertificateOptions {
  /**
   * Maximum age of the certificate in milliseconds
   * Default: 24 hours
   */
  maxAgeMs?: number;

  /**
   * Expected KMS enclave object ID (optional)
   * If provided, the certificate's KMS enclave object ID must match this value
   */
  expectedKmsEnclaveId?: string;

  /**
   * Expected target enclave config ID (optional)
   * If provided, the certificate's target enclave config ID must match this value
   */
  expectedTargetConfigId?: string;

  /**
   * Expected enclave type (optional)
   * If provided, the certificate's enclave type must match this value
   */
  expectedEnclaveType?: string;
}

/**
 * Result of certificate verification
 */
export interface VerificationResult {
  /**
   * Whether the certificate is valid
   */
  isValid: boolean;

  /**
   * Error message if verification failed
   */
  error?: string;

  /**
   * Details about what was verified
   */
  details?: {
    signatureValid: boolean;
    timestampValid: boolean;
    kmsEnclaveIdValid: boolean;
    targetConfigIdValid: boolean;
    enclaveTypeValid: boolean;
    certificateAge: number;
  };
}

/**
 * Reconstructs the intent that was signed for the certificate
 * This must match exactly how the certificate was created in createPublicKeyCertificate
 */
function reconstructCertificateIntent(
  certificate: PublicKeyCertificate,
): Uint8Array {
  const intent = bcs
    .struct('Intent', {
      intent: bcs.u8(),
      timestamp_ms: bcs.u64(),
      data: bcs.struct('PublicKeyCertificate', {
        derived_public_key: bcs.byteVector(),
        kms_enclave_object_id: bcs.byteVector(),
        kms_enclave_public_key: bcs.byteVector(),
        target_enclave_config_id: bcs.byteVector(),
        enclave_type: bcs.string(),
      }),
    })
    .serialize({
      intent: PUBLIC_KEY_CERTIFICATE_INTENT,
      timestamp_ms: certificate.issued_at_ms,
      data: {
        derived_public_key: Buffer.from(certificate.derived_public_key, 'hex'),
        kms_enclave_object_id: Buffer.from(
          certificate.kms_enclave_object_id.replace('0x', ''),
          'hex',
        ),
        kms_enclave_public_key: Buffer.from(
          certificate.kms_enclave_public_key,
          'hex',
        ),
        target_enclave_config_id: Buffer.from(
          certificate.target_enclave_config_id.replace('0x', ''),
          'hex',
        ),
        enclave_type: certificate.enclave_type,
      },
    });

  return intent.toBytes();
}

/**
 * Verifies the signature on a PublicKeyCertificate
 *
 * This function validates that the certificate was signed by the KMS enclave's private key
 * by reconstructing the signed intent and verifying the signature.
 *
 * @param certificate The certificate to verify
 * @returns true if the signature is valid, false otherwise
 */
export function verifyCertificateSignature(
  certificate: PublicKeyCertificate,
): boolean {
  try {
    // Reconstruct the intent that was signed
    const intentBytes = reconstructCertificateIntent(certificate);

    // Parse the signature and public key
    const signature = Buffer.from(certificate.signature, 'hex');
    const publicKey = Buffer.from(certificate.kms_enclave_public_key, 'hex');

    // Verify the signature
    return verifyEd25519Signature(
      Buffer.from(intentBytes),
      signature,
      publicKey,
    );
  } catch (error) {
    console.error('Error verifying certificate signature:', error);
    return false;
  }
}

/**
 * Validates a PublicKeyCertificate with comprehensive checks
 *
 * This function performs multiple validation checks:
 * 1. Signature verification - ensures the certificate was signed by the KMS enclave
 * 2. Timestamp validation - checks if the certificate is still valid (not expired)
 * 3. KMS enclave ID validation - optionally verifies the KMS enclave object ID
 * 4. Target config ID validation - optionally verifies the target enclave config ID
 * 5. Enclave type validation - optionally verifies the enclave type
 *
 * @param certificate The certificate to validate
 * @param options Validation options
 * @returns Verification result with details
 */
export function validateCertificate(
  certificate: PublicKeyCertificate,
  options: VerifyCertificateOptions = {},
): VerificationResult {
  const {
    maxAgeMs = 24 * 60 * 60 * 1000, // 24 hours default
    expectedKmsEnclaveId,
    expectedTargetConfigId,
    expectedEnclaveType,
  } = options;

  const details = {
    signatureValid: false,
    timestampValid: false,
    kmsEnclaveIdValid: true, // Start as true, set to false if check fails
    targetConfigIdValid: true,
    enclaveTypeValid: true,
    certificateAge: 0,
  };

  // 1. Verify signature
  details.signatureValid = verifyCertificateSignature(certificate);
  if (!details.signatureValid) {
    return {
      isValid: false,
      error: 'Certificate signature verification failed',
      details,
    };
  }

  // 2. Validate timestamp
  const now = Date.now();
  const certificateAge = now - certificate.issued_at_ms;
  details.certificateAge = certificateAge;

  if (certificateAge < 0) {
    details.timestampValid = false;
    return {
      isValid: false,
      error: 'Certificate issued in the future (invalid timestamp)',
      details,
    };
  }

  if (certificateAge > maxAgeMs) {
    details.timestampValid = false;
    return {
      isValid: false,
      error: `Certificate expired (age: ${Math.floor(certificateAge / 1000)}s, max: ${Math.floor(maxAgeMs / 1000)}s)`,
      details,
    };
  }

  details.timestampValid = true;

  // 3. Validate KMS enclave object ID (if expected value provided)
  if (expectedKmsEnclaveId) {
    const normalizedExpected = expectedKmsEnclaveId.toLowerCase();
    const normalizedActual = certificate.kms_enclave_object_id.toLowerCase();

    if (normalizedExpected !== normalizedActual) {
      details.kmsEnclaveIdValid = false;
      return {
        isValid: false,
        error: `KMS enclave object ID mismatch (expected: ${expectedKmsEnclaveId}, got: ${certificate.kms_enclave_object_id})`,
        details,
      };
    }
  }

  // 4. Validate target enclave config ID (if expected value provided)
  if (expectedTargetConfigId) {
    const normalizedExpected = expectedTargetConfigId.toLowerCase();
    const normalizedActual = certificate.target_enclave_config_id.toLowerCase();

    if (normalizedExpected !== normalizedActual) {
      details.targetConfigIdValid = false;
      return {
        isValid: false,
        error: `Target enclave config ID mismatch (expected: ${expectedTargetConfigId}, got: ${certificate.target_enclave_config_id})`,
        details,
      };
    }
  }

  // 5. Validate enclave type (if expected value provided)
  if (expectedEnclaveType) {
    if (expectedEnclaveType !== certificate.enclave_type) {
      details.enclaveTypeValid = false;
      return {
        isValid: false,
        error: `Enclave type mismatch (expected: ${expectedEnclaveType}, got: ${certificate.enclave_type})`,
        details,
      };
    }
  }

  return {
    isValid: true,
    details,
  };
}

/**
 * Extracts and returns key information from a certificate without validation
 * Useful for displaying certificate details or logging
 *
 * @param certificate The certificate to inspect
 * @returns Formatted certificate information
 */
export function inspectCertificate(certificate: PublicKeyCertificate): {
  derivedPublicKey: string;
  kmsEnclaveId: string;
  kmsPublicKey: string;
  targetConfigId: string;
  enclaveType: string;
  issuedAt: Date;
  age: string;
} {
  const age = Date.now() - certificate.issued_at_ms;
  const ageSeconds = Math.floor(age / 1000);
  const ageMinutes = Math.floor(ageSeconds / 60);
  const ageHours = Math.floor(ageMinutes / 60);

  let ageString: string;
  if (ageHours > 0) {
    ageString = `${ageHours}h ${ageMinutes % 60}m`;
  } else if (ageMinutes > 0) {
    ageString = `${ageMinutes}m ${ageSeconds % 60}s`;
  } else {
    ageString = `${ageSeconds}s`;
  }

  return {
    derivedPublicKey: certificate.derived_public_key,
    kmsEnclaveId: certificate.kms_enclave_object_id,
    kmsPublicKey: certificate.kms_enclave_public_key,
    targetConfigId: certificate.target_enclave_config_id,
    enclaveType: certificate.enclave_type,
    issuedAt: new Date(certificate.issued_at_ms),
    age: ageString,
  };
}

/**
 * Quick validation function for common use cases
 * Uses sensible defaults for most scenarios
 *
 * @param certificate The certificate to validate
 * @param trustedKmsEnclaveId The trusted KMS enclave object ID
 * @returns true if certificate is valid and trusted, false otherwise
 */
export function isValidCertificate(
  certificate: PublicKeyCertificate,
  trustedKmsEnclaveId: string,
): boolean {
  const result = validateCertificate(certificate, {
    expectedKmsEnclaveId: trustedKmsEnclaveId,
    maxAgeMs: 24 * 60 * 60 * 1000, // 24 hours
  });

  return result.isValid;
}
```

### Certificate Verification API

The certificate verifier provides several functions for different use cases:

#### 1. Basic Signature Verification

Verify that a certificate was signed by the KMS enclave:

```typescript
import { verifyCertificateSignature } from './certificate-verifier.js';

const isValid = verifyCertificateSignature(certificate);
if (isValid) {
  console.log('Certificate signature is valid');
}
```

#### 2. Full Certificate Validation

Validate a certificate with comprehensive checks (signature, timestamp, KMS ID, etc.):

```typescript
import { validateCertificate } from './certificate-verifier.js';

const result = validateCertificate(certificate, {
  maxAgeMs: 60 * 60 * 1000,              // Accept certificates up to 1 hour old
  expectedKmsEnclaveId: '0x123...',      // Verify KMS enclave ID
  expectedTargetConfigId: '0x456...',    // Verify target config ID (optional)
  expectedEnclaveType: '0x789::module::EnclaveConfig<0xabc::app::MyApp>'
});

if (result.isValid) {
  console.log('Certificate is fully valid');
  console.log('Details:', result.details);
} else {
  console.error('Certificate validation failed:', result.error);
}
```

#### 3. Quick Validation (Recommended)

Most common use case - quickly check if a certificate is valid and from a trusted KMS:

```typescript
import { isValidCertificate } from './certificate-verifier.js';

const trustedKmsId = '0x123...'; // Your trusted KMS enclave ID

if (isValidCertificate(certificate, trustedKmsId)) {
  // Certificate is valid and from trusted KMS
  const publicKey = certificate.derived_public_key;
  // Use the public key...
}
```

#### 4. Certificate Inspection

Extract and display certificate information without validation:

```typescript
import { inspectCertificate } from './certificate-verifier.js';

const info = inspectCertificate(certificate);
console.log('Derived Public Key:', info.derivedPublicKey);
console.log('KMS Enclave ID:', info.kmsEnclaveId);
console.log('Enclave Type:', info.enclaveType);
console.log('Issued At:', info.issuedAt.toISOString());
console.log('Age:', info.age); // e.g., "5m 30s"
```

### Validation Options

```typescript
interface VerifyCertificateOptions {
  // Maximum age of the certificate in milliseconds
  // Default: 24 hours
  maxAgeMs?: number;

  // Expected KMS enclave object ID (optional)
  // If provided, the certificate's KMS enclave object ID must match
  expectedKmsEnclaveId?: string;

  // Expected target enclave config ID (optional)
  expectedTargetConfigId?: string;

  // Expected enclave type (optional)
  expectedEnclaveType?: string;
}
```

### Verification Result

```typescript
interface VerificationResult {
  isValid: boolean;
  error?: string;
  details?: {
    signatureValid: boolean;
    timestampValid: boolean;
    kmsEnclaveIdValid: boolean;
    targetConfigIdValid: boolean;
    enclaveTypeValid: boolean;
    certificateAge: number; // in milliseconds
  };
}
```

### Common Usage Examples

#### Example 1: Verifying API Response Certificate

```typescript
// After receiving a response from Seal KMS
const response = await fetch('http://<seal-kms-endpoint>/enclave-key', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(request),
});

const data = await response.json();

if (data.success && data.public_key_certificate) {
  const certificate = data.public_key_certificate;

  // Verify the certificate is from your trusted KMS
  const trustedKmsId = '0xabc...'; // Your trusted KMS enclave ID

  if (isValidCertificate(certificate, trustedKmsId)) {
    console.log('✓ Certificate is valid and trusted');

    // Verify the certificate's derived key matches the response
    if (certificate.derived_public_key === data.derived_public_key) {
      console.log('✓ Public key consistency check passed');
      // Safe to use the derived public key
    }
  } else {
    console.error('✗ Certificate validation failed');
    // Do not trust the response
  }
}
```

#### Example 2: Custom Validation Requirements

```typescript
// Scenario: You only accept very recent certificates (5 minutes)
// and verify they're for a specific enclave type
const result = validateCertificate(certificate, {
  maxAgeMs: 5 * 60 * 1000, // 5 minutes
  expectedEnclaveType: '0x123::module::EnclaveConfig<0x456::app::MyApp>',
  expectedKmsEnclaveId: '0xabc...', // Your trusted KMS enclave ID
});

if (result.isValid) {
  console.log('✓ Certificate meets all custom requirements');
} else {
  console.log('✗ Certificate failed custom validation');
  console.log('  Reason:', result.error);
  console.log('  Details:', result.details);
}
```

#### Example 3: Batch Certificate Validation

```typescript
const trustedKmsId = '0xabc...';
const certificates = [...]; // Array of certificates

const results = certificates.map((cert, index) => {
  const isValid = isValidCertificate(cert, trustedKmsId);
  return { index, isValid, enclaveType: cert.enclave_type };
});

const validCount = results.filter(r => r.isValid).length;
console.log(`Validated ${certificates.length} certificates: ${validCount} valid`);

results.forEach(result => {
  const status = result.isValid ? '✓' : '✗';
  console.log(`  ${status} Certificate ${result.index}: ${result.enclaveType}`);
});
```

#### Example 4: Displaying Certificate Information

```typescript
const info = inspectCertificate(certificate);

console.log('Certificate Information:');
console.log('  Derived Public Key:', info.derivedPublicKey);
console.log('  KMS Enclave ID:', info.kmsEnclaveId);
console.log('  Target Config ID:', info.targetConfigId);
console.log('  Enclave Type:', info.enclaveType);
console.log('  Issued At:', info.issuedAt.toISOString());
console.log('  Age:', info.age);
```

### Security Best Practices

1. **Always Verify Certificates**: Never trust public keys from API responses without verifying the certificate signature
2. **Check KMS Enclave ID**: Always provide `expectedKmsEnclaveId` to ensure the certificate is from your trusted KMS
3. **Validate Freshness**: Use appropriate `maxAgeMs` values based on your security requirements (shorter is better)
4. **Verify Consistency**: Check that the certificate's `derived_public_key` matches the response's `derived_public_key`
5. **Validate Enclave Type**: Use `expectedEnclaveType` to ensure the key was derived for the correct enclave

### How Certificate Signing Works

The KMS enclave signs certificates using the following process:

1. Creates an intent structure with type `PUBLIC_KEY_CERTIFICATE_INTENT = 4`
2. Includes the timestamp and certificate data in the intent
3. Serializes the intent using BCS (Binary Canonical Serialization)
4. Signs the serialized intent with the KMS enclave's Ed25519 private key

The verification process reconstructs this same intent and verifies the signature matches, proving the certificate was created by the legitimate KMS enclave.

### Integration Notes

When integrating the certificate verifier into your client application:

1. **Copy the implementation** from the code block above into your project
2. **Implement `verifyEd25519Signature`** - This should use your preferred crypto library (e.g., `@noble/ed25519`, `tweetnacl`, or Node.js `crypto`)
3. **Define the `PublicKeyCertificate` type** - Import from your KMS response types or define it locally
4. **Install dependencies**: `npm install @mysten/bcs`

Example Ed25519 signature verification using `@noble/ed25519`:

```typescript
import { ed25519 } from '@noble/curves/ed25519';

export function verifyEd25519Signature(
  message: Buffer,
  signature: Buffer,
  publicKey: Buffer,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch (error) {
    return false;
  }
}
```

## Key Server Management

### Automatic Key Rotation

The system automatically rotates the master key when you change `server_object_ids` in the config.

**How it works:**
1. The Seal encrypted object contains server IDs in its `services` field
2. On startup, the system parses the encrypted object to extract which servers were used
3. If they differ from the current config, automatic rotation occurs:
   - Decrypts master key using old servers (from encrypted object)
   - Re-encrypts using new servers (from current config)  
   - Updates on-chain storage

**Example:**
```yaml
# Initial config
server_object_ids:
  - "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75"
  - "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"

# Change servers and restart → automatic rotation!
server_object_ids:
  - "0x5466b7df5c15b508678d51496ada8afab0d6f70a01c10613123382b1b8131007"
  - "0x9c949e53c36ab7a9c484ed9e8b43267a77d4b8d70e79aa6b39042e3d4c434105"
```

**Logs during rotation:**
```
Server object IDs have changed, rotating master key...
Old server IDs: [0x73d05d62..., 0xf5d14a81...]
New server IDs: [0x5466b7df..., 0x9c949e53...]
Decrypting master key with old servers...
Master key decrypted with old servers
Master key re-encrypted with new servers
Master key rotated successfully.
```

### Key Server Availability Checking

The system automatically verifies key servers when encrypting to ensure they are responding.

**How it works:**
- When creating a master key or rotating keys, the system:
  1. Retrieves server details from on-chain (includes URLs)
  2. Pings each server to verify it's responding
  3. Verifies proof of possession (PoP) from each server
  4. Throws an error if any server is unavailable

**For decryption:**
- Server verification is skipped to speed up enclave startup
- Decryption only needs servers that are actually available at decryption time

**No configuration needed** - verification happens automatically for all encryption operations.

### Parse Encrypted Object

Extract metadata from a Seal encrypted object:

```typescript
import { parseEncryptedObject } from './app/master-key.js';

const { serverObjectIds, threshold, packageId, id } = 
  parseEncryptedObject(encryptedKeyHex);

console.log('Encrypted with servers:', serverObjectIds);
console.log('Requires', threshold, 'servers to decrypt');
```
