import crypto from 'node:crypto';
import { bcs } from '@mysten/bcs';
import {
  validateRemoteAttestation,
  verifyEd25519Signature,
} from './attestation-validator.js';
import { configManager } from './config.js';
import { getCurrentMasterKey } from './master-key.js';

// Intent type for enclave key requests
const ENCLAVE_KEY_REQUEST_INTENT = 2;
// Intent type for enclave key responses
const ENCLAVE_KEY_RESPONSE_INTENT = 3;
// Intent type for public key certificate
const PUBLIC_KEY_CERTIFICATE_INTENT = 4;

/**
 * Request structure for enclave private key
 */
export interface EnclaveKeyRequest {
  // Ephemeral public key from the client enclave (for response encryption)
  ephemeral_public_key: string; // hex encoded
  // Attestation document from the client enclave
  attestation_document: string; // hex encoded
  // Client enclave's config object ID on Sui (contains the type info)
  enclave_config_object_id: string;
  // Timestamp for the request
  timestamp_ms: number;
  // Signature of the intent using the enclave's Ed25519 private key
  signature: string; // hex encoded
}

/**
 * Certificate for the derived public key with KMS enclave metadata
 */
export interface PublicKeyCertificate {
  // Public key of the derived key pair (hex encoded)
  derived_public_key: string;
  // KMS enclave object ID on Sui
  kms_enclave_object_id: string;
  // KMS enclave public key (hex encoded)
  kms_enclave_public_key: string;
  // Target enclave config object ID
  target_enclave_config_id: string;
  // Enclave type for which the key was derived
  enclave_type: string;
  // Timestamp when certificate was issued
  issued_at_ms: number;
  // Signature of the certificate by KMS enclave (hex encoded)
  signature: string;
}

/**
 * Response structure for enclave private key
 */
export interface EnclaveKeyResponse {
  // Encrypted private key (encrypted with ephemeral public key)
  encrypted_private_key: string; // hex encoded
  // IV for the encryption
  iv: string; // hex encoded
  // Auth tag for AES-GCM
  auth_tag: string; // hex encoded
  // Server's ephemeral public key for ECDH
  server_public_key: string; // hex encoded
  // Enclave config type that was used for derivation
  derived_for: string;
  // Timestamp
  timestamp_ms: number;
  // Signature of the response using sign_intent
  signature: string; // hex encoded
  // Current enclave object ID for client validation
  enclave_object_id: string;
  // Signed public key certificate for verification chain
  public_key_certificate: PublicKeyCertificate;
}

/**
 * Derives a deterministic private key from the master key for a specific enclave type
 */
function derivePrivateKeyForEnclave(
  masterKey: Buffer,
  enclaveType: string,
): Buffer {
  // Use HKDF to derive an enclave-type-specific key
  const salt = Buffer.from('seal-kms-enclave-key');
  const info = Buffer.from(enclaveType);

  // HKDF with SHA-256
  const key = crypto.hkdfSync('sha256', masterKey, salt, info, 32);
  return Buffer.from(key);
}

/**
 * Derives the Ed25519 public key from a private key seed
 */
function derivePublicKey(privateKeySeed: Buffer): Buffer {
  // Create a private key object from raw seed (32 bytes for Ed25519)
  // Ed25519 private key in raw format is 32 bytes
  const privateKeyDer = Buffer.concat([
    // ASN.1 DER header for Ed25519 private key
    Buffer.from([
      0x30,
      0x2e, // SEQUENCE (46 bytes)
      0x02,
      0x01,
      0x00, // INTEGER version = 0
      0x30,
      0x05, // SEQUENCE (5 bytes) - algorithm identifier
      0x06,
      0x03,
      0x2b,
      0x65,
      0x70, // OID 1.3.101.112 (Ed25519)
      0x04,
      0x22, // OCTET STRING (34 bytes)
      0x04,
      0x20, // OCTET STRING (32 bytes) - the actual key
    ]),
    privateKeySeed,
  ]);

  const privateKeyObject = crypto.createPrivateKey({
    key: privateKeyDer,
    format: 'der',
    type: 'pkcs8',
  });

  // Extract the public key
  const publicKeyObject = crypto.createPublicKey(privateKeyObject);
  const publicKeyDer = publicKeyObject.export({
    format: 'der',
    type: 'spki',
  }) as Buffer;

  // Extract raw 32-byte public key from DER format
  // Ed25519 public key in SPKI format: last 32 bytes
  return publicKeyDer.subarray(-32);
}

/**
 * Fetches the KMS enclave's public key
 */
async function getKmsEnclavePublicKey(): Promise<string> {
  const config = await configManager.loadConfig();
  const enclaveEndpoint = config.seal.enclave_endpoint;

  const response = await fetch(`${enclaveEndpoint}/public_key`);

  if (!response.ok) {
    throw new Error(`Failed to get public key: ${response.statusText}`);
  }

  const { public_key } = (await response.json()) as { public_key: string };
  return public_key;
}

/**
 * Encrypts data using ECIES with the ephemeral public key
 */
function encryptWithEphemeralKey(
  data: Buffer,
  ephemeralPublicKey: Buffer,
): { encrypted: Buffer; iv: Buffer; authTag: Buffer; serverPublicKey: Buffer } {
  // Generate a shared secret using ECDH
  // For simplicity, we'll use AES-256-GCM with a derived key

  // Create a temporary key pair for ECDH
  const ecdh = crypto.createECDH('prime256v1');
  const serverPublicKey = ecdh.generateKeys();

  // Compute shared secret
  const sharedSecret = ecdh.computeSecret(ephemeralPublicKey);

  // Derive encryption key using HKDF
  const encryptionKey = Buffer.from(
    crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from('encryption'),
      Buffer.from('seal-kms'),
      32,
    ),
  );

  // Encrypt using AES-256-GCM
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { encrypted, iv, authTag, serverPublicKey };
}

/**
 * Signs the enclave key response using sign_intent
 */
async function signEnclaveKeyResponse(
  response: Omit<
    EnclaveKeyResponse,
    'signature' | 'enclave_object_id' | 'public_key_certificate'
  >,
): Promise<{ signature: string; enclave_object_id: string }> {
  const enclaveObjectId = configManager.getEnclaveObjectId();
  if (!enclaveObjectId) {
    throw new Error('Enclave object ID not configured');
  }

  // Create intent for the response
  const intent = bcs
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
        encrypted_private_key: Buffer.from(
          response.encrypted_private_key,
          'hex',
        ),
        iv: Buffer.from(response.iv, 'hex'),
        auth_tag: Buffer.from(response.auth_tag, 'hex'),
        server_public_key: Buffer.from(response.server_public_key, 'hex'),
        derived_for: response.derived_for,
      },
    });

  // Get the enclave endpoint from config
  const config = await configManager.loadConfig();
  const enclaveEndpoint = config.seal.enclave_endpoint;

  // Sign the intent using the enclave's sign_intent endpoint
  const signResponse = await fetch(`${enclaveEndpoint}/sign_intent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload: intent.toHex() }),
  });

  if (!signResponse.ok) {
    throw new Error(`Failed to sign response: ${signResponse.statusText}`);
  }

  const { signature } = (await signResponse.json()) as { signature: string };

  return {
    signature,
    enclave_object_id: enclaveObjectId,
  };
}

/**
 * Creates and signs a public key certificate for a derived key
 */
async function createPublicKeyCertificate(
  derivedPublicKey: Buffer,
  enclaveType: string,
  targetEnclaveConfigId: string,
  timestamp: number,
): Promise<PublicKeyCertificate> {
  const enclaveObjectId = configManager.getEnclaveObjectId();
  if (!enclaveObjectId) {
    throw new Error('Enclave object ID not configured');
  }

  // Get the KMS enclave's public key
  const kmsPublicKey = await getKmsEnclavePublicKey();

  // Create certificate data (without signature)
  const certificateData = {
    derived_public_key: derivedPublicKey.toString('hex'),
    kms_enclave_object_id: enclaveObjectId,
    kms_enclave_public_key: kmsPublicKey,
    target_enclave_config_id: targetEnclaveConfigId,
    enclave_type: enclaveType,
    issued_at_ms: timestamp,
  };

  // Create intent for the certificate
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
      timestamp_ms: timestamp,
      data: {
        derived_public_key: derivedPublicKey,
        kms_enclave_object_id: Buffer.from(
          enclaveObjectId.replace('0x', ''),
          'hex',
        ),
        kms_enclave_public_key: Buffer.from(kmsPublicKey, 'hex'),
        target_enclave_config_id: Buffer.from(
          targetEnclaveConfigId.replace('0x', ''),
          'hex',
        ),
        enclave_type: enclaveType,
      },
    });

  // Get the enclave endpoint from config
  const config = await configManager.loadConfig();
  const enclaveEndpoint = config.seal.enclave_endpoint;

  // Sign the intent using the enclave's sign_intent endpoint
  const signResponse = await fetch(`${enclaveEndpoint}/sign_intent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload: intent.toHex() }),
  });

  if (!signResponse.ok) {
    throw new Error(`Failed to sign certificate: ${signResponse.statusText}`);
  }

  const { signature } = (await signResponse.json()) as { signature: string };

  return {
    ...certificateData,
    signature,
  };
}

/**
 * Validates the intent signature from the client enclave
 */
async function validateIntentSignature(
  signature: Buffer,
  publicKey: Buffer,
  timestamp: number,
  configObjectId: string,
  ephemeralPublicKey: Buffer,
): Promise<boolean> {
  try {
    // Construct the full intent message
    const intentData = bcs
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
          config_object_id: Buffer.from(
            configObjectId.replace('0x', ''),
            'hex',
          ),
          ephemeral_public_key: ephemeralPublicKey,
        },
      });

    // Convert SerializedBcs to Buffer
    const intent = Buffer.from(intentData.toBytes());

    // Verify signature using Ed25519
    return verifyEd25519Signature(intent, signature, publicKey);
  } catch (error) {
    console.error('Signature validation error:', error);
    return false;
  }
}

/**
 * Processes a request from a client enclave for a private key
 */
export async function processEnclaveKeyRequest(
  request: EnclaveKeyRequest,
): Promise<{ success: boolean; data?: EnclaveKeyResponse; error?: string }> {
  try {
    // Validate timestamp (should be recent - within 5 minutes)
    const now = Date.now();
    const timeDiff = Math.abs(now - request.timestamp_ms);
    if (timeDiff > 5 * 60 * 1000) {
      return {
        success: false,
        error: 'Request timestamp is too old or too far in the future',
      };
    }

    // Validate attestation against the enclave config
    const attestationResult = await validateRemoteAttestation(
      request.attestation_document,
      request.enclave_config_object_id,
    );

    if (!attestationResult.isValid) {
      return {
        success: false,
        error: `Attestation validation failed: ${attestationResult.error}`,
      };
    }

    if (!attestationResult.publicKey) {
      return {
        success: false,
        error: 'Could not extract public key from attestation',
      };
    }

    if (!attestationResult.enclaveType) {
      return {
        success: false,
        error: 'Could not determine enclave type from config object',
      };
    }

    // Check if the enclave is authorized based on its type
    const isAuthorized = await isEnclaveAuthorized(
      attestationResult.enclaveType,
    );
    if (!isAuthorized) {
      return {
        success: false,
        error: `Enclave type not authorized: ${attestationResult.enclaveType}`,
      };
    }

    // Validate the intent signature
    const ephemeralPublicKey = Buffer.from(request.ephemeral_public_key, 'hex');
    const signatureValid = await validateIntentSignature(
      Buffer.from(request.signature, 'hex'),
      attestationResult.publicKey,
      request.timestamp_ms,
      request.enclave_config_object_id,
      ephemeralPublicKey,
    );

    if (!signatureValid) {
      return { success: false, error: 'Invalid intent signature' };
    }

    // Get the current master key
    const { masterKeyBuffer } = getCurrentMasterKey();

    // Derive a private key for this enclave type
    const derivedPrivateKey = derivePrivateKeyForEnclave(
      masterKeyBuffer,
      attestationResult.enclaveType,
    );

    // Derive the public key for the certificate
    const derivedPublicKey = derivePublicKey(derivedPrivateKey);
    console.log('Derived public key:', derivedPublicKey.toString('hex'));

    // Create the public key certificate
    const publicKeyCertificate = await createPublicKeyCertificate(
      derivedPublicKey,
      attestationResult.enclaveType,
      request.enclave_config_object_id,
      now,
    );
    console.log('Public key certificate:', publicKeyCertificate);

    // Encrypt the private key with the ephemeral public key
    const { encrypted, iv, authTag, serverPublicKey } = encryptWithEphemeralKey(
      derivedPrivateKey,
      ephemeralPublicKey,
    );

    // Prepare response without signature
    const responseData = {
      encrypted_private_key: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      auth_tag: authTag.toString('hex'),
      server_public_key: serverPublicKey.toString('hex'),
      derived_for: attestationResult.enclaveType,
      timestamp_ms: now,
    };

    // Sign the response
    const { signature, enclave_object_id } =
      await signEnclaveKeyResponse(responseData);

    // Complete response with signature, enclave object ID, and certificate
    const response: EnclaveKeyResponse = {
      ...responseData,
      signature,
      enclave_object_id,
      public_key_certificate: publicKeyCertificate,
    };

    console.log(
      `Successfully processed key request for enclave type: ${attestationResult.enclaveType}`,
    );

    return { success: true, data: response };
  } catch (error) {
    console.error('Error processing enclave key request:', error);
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : 'Unknown error processing request',
    };
  }
}

/**
 * Validates that the requesting enclave is authorized
 * This can include additional checks like allowlists, rate limiting, etc.
 */
export async function isEnclaveAuthorized(
  _enclaveType: string,
): Promise<boolean> {
  // Implement authorization logic here
  // For example, check against an allowlist of authorized enclave types
  // Or verify the enclave is registered in a specific registry on Sui

  // The enclaveType includes the full type path, e.g.:
  // "0x123::module::EnclaveConfig<0x456::app::MyApp>"
  // This can be used for fine-grained access control

  // For now, we'll allow all valid enclaves
  return true;
}
