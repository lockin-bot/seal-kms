import crypto from 'node:crypto';
import { bcs } from '@mysten/bcs';
import {
  EncryptedObject,
  type KeyServerConfig,
  SealClient,
  SessionKey,
} from '@mysten/seal';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { configManager } from './config.js';

// Hardcoded key ID for consistent encryption/decryption
const KEY_ID = Buffer.from('kms-master-key-101');
const SEAL_INTENT = 0;
const SET_MASTER_KEY_INTENT = 1;

/**
 * Creates a SealClient configured with the current environment settings
 * @param forEncryption - If true, verifies key servers before use (recommended for encryption)
 * @param serverConfigs - Optional override for server configs
 */
export function createSealClient(options?: {
  forEncryption?: boolean;
  serverConfigs?: KeyServerConfig[];
}): {
  client: SealClient;
  suiClient: SuiClient;
  config: ReturnType<typeof configManager.getSealConfig>;
} {
  const sealConfig = configManager.getSealConfig();
  const { sui_network: suiNetwork, server_configs: serverConfigs } = sealConfig;

  const suiClient = new SuiClient({
    url: getFullnodeUrl(suiNetwork as 'testnet' | 'mainnet'),
  });

  // Use provided server configs or fall back to config
  const effectiveServerConfigs = options?.serverConfigs || serverConfigs;

  if (!effectiveServerConfigs || effectiveServerConfigs.length === 0) {
    throw new Error(
      'No server configs configured. Please add server_configs to your config file.',
    );
  }

  // Normalize server configs: ensure weight defaults to 1 if not specified
  const normalizedServerConfigs = effectiveServerConfigs.map((config) => ({
    ...config,
    weight: config.weight ?? 1,
  }));

  console.log('[DEBUG createSealClient] Final server configs passed to SealClient:');
  normalizedServerConfigs.forEach((s, i) => {
    console.log(`  ${i + 1}. ${s.objectId} - weight: ${s.weight} ${s.apiKeyName ? `(API key: ${s.apiKeyName})` : ''}`);
  });

  // Verify key servers if this client will be used for encryption
  const shouldVerify = options?.forEncryption ?? false;

  const client = new SealClient({
    suiClient,
    serverConfigs: normalizedServerConfigs,
    verifyKeyServers: shouldVerify,
  });

  return { client, suiClient, config: sealConfig };
}

/**
 * Encrypts a master key using double encryption (inner AES + Seal)
 * Automatically verifies key servers are available before encryption
 *
 * Security model:
 * 1. Inner AES encryption with Sui secret key (defense against Seal server collusion)
 * 2. Seal encryption with threshold (defense against single server compromise)
 */
export async function encryptMasterKey(masterKey: Buffer): Promise<{
  encryptedKey: string;
}> {
  // Create client with server verification enabled for encryption
  const { client, config } = createSealClient({ forEncryption: true });

  if (!config.enclave_object_id) {
    throw new Error('Enclave not registered - cannot encrypt master key');
  }

  // Get Sui secret key for inner encryption
  const sui_sk = Buffer.from(
    config.sui_secret_key.startsWith('0x')
      ? config.sui_secret_key.substring(2)
      : config.sui_secret_key,
    'hex',
  );

  // First layer: AES encryption with Sui secret key
  // Even if all Seal servers collude, they can't decrypt without this key
  const { encrypted, iv, authTag } = encryptData(masterKey, sui_sk);

  // Concatenate: iv (16 bytes) || encrypted (32 bytes) || authTag (16 bytes) = 64 bytes
  const innerEncrypted = Buffer.concat([iv, encrypted, authTag]);

  // Second layer: Seal threshold encryption
  const { encryptedObject: encryptedBytes } = await client.encrypt({
    threshold: 3,
    packageId: config.kms_package_id,
    id: KEY_ID.toString('hex'),
    data: innerEncrypted,
  });

  return {
    encryptedKey: Buffer.from(encryptedBytes).toString('hex'),
  };
}

/**
 * Decrypts a master key using Seal with enclave attestation
 * Always uses a random ephemeral Sui account for signing
 * Does not verify key servers to speed up startup
 *
 * @param encryptedKeyHex - The encrypted key to decrypt
 */
export async function decryptMasterKey(
  encryptedKeyHex: string,
): Promise<Buffer> {
  // Parse the encrypted object to extract server IDs
  const encryptedBytes = Buffer.from(encryptedKeyHex, 'hex');
  const parsed = EncryptedObject.parse(encryptedBytes);

  // Get configured server configs to retrieve API keys
  const sealConfig = configManager.getSealConfig();
  const configuredServers = new Map(
    sealConfig.server_configs.map((s) => [s.objectId.toLowerCase(), s]),
  );

  // Extract weights from encrypted object by counting server occurrences
  // In Seal, a server with weight N appears N times in the services array
  const serverWeights = new Map<string, number>();
  for (const [objectId, _shareIndex] of parsed.services) {
    const id =
      typeof objectId === 'string'
        ? objectId.startsWith('0x')
          ? objectId
          : `0x${objectId}`
        : `0x${Buffer.from(objectId).toString('hex')}`;

    const normalizedId = id.toLowerCase();
    serverWeights.set(normalizedId, (serverWeights.get(normalizedId) || 0) + 1);
  }

  // Build server configs with weights from encrypted object and API keys from config
  const serverConfigs = Array.from(serverWeights.entries()).map(
    ([normalizedId, weight]) => {
      // Find original casing from configured servers or use normalized
      const configuredServer = configuredServers.get(normalizedId);
      const objectId = configuredServer?.objectId || normalizedId;

      return {
        objectId,
        weight,  // ✅ Extracted from encrypted object
        // Merge API key configuration if available
        ...(configuredServer?.apiKeyName && {
          apiKeyName: configuredServer.apiKeyName,
          apiKey: configuredServer.apiKey,
        }),
      };
    },
  );

  console.log('[DEBUG decryptMasterKey] Extracted server configs from encrypted object:');
  serverConfigs.forEach((s, i) => {
    console.log(`  ${i + 1}. ${s.objectId} - weight: ${s.weight} (from encrypted object)`);
  });

  // Create client without server verification for faster decryption
  const { client, suiClient, config } = createSealClient({
    forEncryption: false,
    serverConfigs,
  });
  const {
    kms_package_id: packageId,
    module_name: moduleName,
    enclave_endpoint: enclaveEndpoint,
    enclave_object_id: configEnclaveObjectId,
  } = config;

  // Use the specific enclave object ID if provided, otherwise use the one from config
  const enclaveObjectId = configEnclaveObjectId;

  if (!enclaveObjectId) {
    throw new Error('Enclave not registered - cannot decrypt master key');
  }

  // Always use a random ephemeral keypair
  const keypair = new Ed25519Keypair();

  const suiAddress = keypair.getPublicKey().toSuiAddress();

  let sessionKey = await SessionKey.create({
    address: suiAddress,
    packageId,
    ttlMin: 10,
    suiClient,
  });
  sessionKey = SessionKey.import(
    {
      ...sessionKey.export(),
      // Backdate by 5 minutes to avoid clock skew issues
      creationTimeMs: Date.now() - 5 * 60 * 1000,
    },
    suiClient,
  );

  const message = sessionKey.getPersonalMessage();
  const { signature } = await keypair.signPersonalMessage(message);
  sessionKey.setPersonalMessageSignature(signature);

  const now = Date.now();

  const intent = bcs
    .struct('Intent', {
      intent: bcs.u8(),
      timestamp_ms: bcs.u64(),
      data: bcs.struct('SealRequest', {
        timestamp_ms: bcs.u64(),
        id: bcs.byteVector(),
        requester: bcs.byteVector(),
      }),
    })
    .serialize({
      intent: SEAL_INTENT,
      timestamp_ms: now,
      data: {
        timestamp_ms: now,
        id: KEY_ID,
        requester: Buffer.from(suiAddress.substring(2), 'hex'),
      },
    });

  const response = await fetch(`${enclaveEndpoint}/sign_intent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload: intent.toHex() }),
  });

  if (!response.ok) {
    throw new Error(`Failed to sign intent: ${response.statusText}`);
  }

  const { signature: enclaveSignature } = (await response.json()) as {
    signature: string;
  };

  const tx = new Transaction();
  tx.moveCall({
    target: `${packageId}::${moduleName}::seal_approve`,
    arguments: [
      tx.pure.vector('u8', KEY_ID),
      tx.pure.u64(now),
      tx.pure.vector('u8', Buffer.from(enclaveSignature, 'hex')),
      tx.object(enclaveObjectId),
    ],
  });

  console.log(
    `Decrypting master key with enclave ${enclaveObjectId}, using client address ${suiAddress} private key ${keypair.getSecretKey()}, timestamp: ${now}`,
  );
  // the object id might not be available yet, so we need to retry
  const txBytes = await (async () => {
    for (let i = 0; i < 30; i++) {
      try {
        return await tx.build({
          client: suiClient,
          onlyTransactionKind: true,
        });
      } catch (e) {
        console.error(`Error building transaction: ${e}`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    throw new Error('Failed to build transaction after 30 attempts');
  })();

  console.log(`Personal message: ${new TextDecoder().decode(message)}`);
  const exportedSessionKey = sessionKey.export();
  console.log(
    `Session key:\n${JSON.stringify(Object.fromEntries(Object.entries(exportedSessionKey)))}`,
  );
  console.log(
    `Transaction bytes:\n${Buffer.from(txBytes as unknown as WithImplicitCoercion<ArrayBufferLike>, txBytes.byteOffset, txBytes.byteLength).toString('hex')}`,
  );

  // Seal decryption - gets the inner AES encrypted data
  const decryptedBytes = await client.decrypt({
    data: encryptedBytes,
    sessionKey,
    txBytes,
  });

  // The decrypted data is: iv (16 bytes) || encrypted (32 bytes) || authTag (16 bytes)
  const innerEncrypted = Buffer.from(decryptedBytes);

  if (innerEncrypted.length !== 64) {
    throw new Error(
      `Invalid decrypted data length: expected 64 bytes, got ${innerEncrypted.length}`,
    );
  }

  const iv = innerEncrypted.subarray(0, 16);
  const encrypted = innerEncrypted.subarray(16, 48);
  const authTag = innerEncrypted.subarray(48, 64);

  // Get Sui secret key for inner decryption
  const sui_sk = Buffer.from(
    config.sui_secret_key.startsWith('0x')
      ? config.sui_secret_key.substring(2)
      : config.sui_secret_key,
    'hex',
  );

  // Inner AES decryption
  return decryptData(encrypted, sui_sk, iv, authTag);
}

/**
 * Encrypts data using AES-256-GCM (returns Buffers)
 */
export function encryptData(
  data: Buffer,
  key: Buffer,
): {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
} {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv,
    authTag,
  };
}

/**
 * Decrypts data using AES-256-GCM (accepts Buffers)
 */
export function decryptData(
  encrypted: Buffer,
  key: Buffer,
  iv: Buffer,
  authTag: Buffer,
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted;
}

export function decryptDataHex(
  encryptedHex: string,
  key: string,
  ivHex: string,
  authTagHex: string,
): Buffer {
  return decryptData(
    Buffer.from(encryptedHex, 'hex'),
    Buffer.from(key, 'hex'),
    Buffer.from(ivHex, 'hex'),
    Buffer.from(authTagHex, 'hex'),
  );
}

// ======= Core Master Key Lifecycle Functions =======

import type { WithImplicitCoercion } from 'node:buffer';

// In-memory storage for the current master key
let currentMasterKey: {
  masterKey: string;
  masterKeyBuffer: Buffer; // Binary version for efficiency
  encryptedKey: string;
} | null = null;

/**
 * Get the current master key from memory
 * @throws Error if master key has not been initialized
 */
export function getCurrentMasterKey() {
  if (!currentMasterKey) {
    throw new Error(
      'Master key not initialized. Call initializeMasterKey() first.',
    );
  }
  return currentMasterKey;
}

/**
 * Check if master key has been initialized
 */
export function isMasterKeyInitialized(): boolean {
  return currentMasterKey !== null;
}

async function retrieveMasterKey() {
  const { sui_network: suiNetwork, encrypted_master_key_object_id } =
    configManager.getSealConfig();

  const suiClient = new SuiClient({
    url: getFullnodeUrl(suiNetwork as 'testnet' | 'mainnet'),
  });
  const obj = await suiClient.getObject({
    id: encrypted_master_key_object_id,
    options: {
      showContent: true,
    },
  });
  const content = obj?.data?.content;
  if (content?.dataType !== 'moveObject' || !('fields' in content)) {
    console.warn(
      'Encrypted master key object not found or invalid:',
      JSON.stringify(obj, null, 2),
    );
    throw new Error('Encrypted master key object not found or invalid');
  }
  const fields = content.fields as {
    encrypted_key: number[];
    version: string;
    updated_at: string;
  };
  if (Number(fields.version) < 1) {
    return null;
  }

  // The encrypted_key is directly the Seal encrypted object
  const sealEncryptedKey = Buffer.from(fields.encrypted_key).toString('hex');

  // Parse the Seal encrypted object to extract server IDs and weights
  const encryptedBytes = Buffer.from(sealEncryptedKey, 'hex');
  const parsed = EncryptedObject.parse(encryptedBytes);

  // Get configured server configs to retrieve API keys
  const sealConfig = configManager.getSealConfig();
  const configuredServers = new Map(
    sealConfig.server_configs.map((s) => [s.objectId.toLowerCase(), s]),
  );

  // Extract weights from encrypted object by counting server occurrences
  // In Seal, a server with weight N appears N times in the services array
  const serverWeights = new Map<string, number>();
  for (const [objectId, _shareIndex] of parsed.services) {
    const id =
      typeof objectId === 'string'
        ? objectId.startsWith('0x')
          ? objectId
          : `0x${objectId}`
        : `0x${Buffer.from(objectId).toString('hex')}`;

    const normalizedId = id.toLowerCase();
    serverWeights.set(normalizedId, (serverWeights.get(normalizedId) || 0) + 1);
  }

  // Build server configs with weights from encrypted object and API keys from config
  const serverConfigs = Array.from(serverWeights.entries()).map(
    ([normalizedId, weight]) => {
      // Find original casing from configured servers or use normalized
      const configuredServer = configuredServers.get(normalizedId);
      const objectId = configuredServer?.objectId || normalizedId;

      return {
        objectId,
        weight,  // ✅ Extracted from encrypted object
        // Merge API key configuration if available
        ...(configuredServer?.apiKeyName && {
          apiKeyName: configuredServer.apiKeyName,
          apiKey: configuredServer.apiKey,
        }),
      };
    },
  );

  return {
    encrypted_key: sealEncryptedKey,
    version: Number(fields.version),
    updated_at: Number(fields.updated_at),
    server_configs: serverConfigs,
  };
}

async function storeMasterKey(encryptedKey: string) {
  const {
    module_name: moduleName,
    kms_package_id: kmsPackageId,
    encrypted_master_key_object_id,
    sui_network: suiNetwork,
    enclave_endpoint: enclaveEndpoint,
    sui_secret_key: suiSecretKey,
  } = configManager.getSealConfig();
  const enclaveObjectId = configManager.getEnclaveObjectId();
  if (enclaveObjectId == null) {
    throw new Error('Enclave not registered - cannot store master key');
  }

  // The encryptedKey is already double-encrypted (inner AES + Seal)
  // Store it directly on-chain without additional outer encryption
  const sealEncryptedBytes = Buffer.from(encryptedKey, 'hex');

  const now = Date.now();

  const intent = bcs
    .struct('Intent', {
      intent: bcs.u8(),
      timestamp_ms: bcs.u64(),
      data: bcs.struct('SetMasterKeyRequest', {
        encrypted_key: bcs.byteVector(),
      }),
    })
    .serialize({
      intent: SET_MASTER_KEY_INTENT,
      timestamp_ms: now,
      data: {
        encrypted_key: sealEncryptedBytes,
      },
    });

  const response = await fetch(`${enclaveEndpoint}/sign_intent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload: intent.toHex() }),
  });

  if (!response.ok) {
    throw new Error(`Failed to sign intent: ${response.statusText}`);
  }

  const { signature: enclaveSignature } = (await response.json()) as {
    signature: string;
  };

  // Initialize Sui client
  const suiClient = new SuiClient({
    url: getFullnodeUrl(suiNetwork as 'testnet' | 'mainnet'),
  });

  // Create keypair from secret key
  const sui_sk = Buffer.from(
    suiSecretKey.startsWith('0x') ? suiSecretKey.substring(2) : suiSecretKey,
    'hex',
  );
  const keypair = Ed25519Keypair.fromSecretKey(sui_sk);

  // Build the transaction
  const tx = new Transaction();

  // Set master key with Seal encrypted object
  tx.moveCall({
    target: `${kmsPackageId}::${moduleName}::set_master_key`,
    typeArguments: [],
    arguments: [
      tx.object(encrypted_master_key_object_id),
      tx.object(enclaveObjectId),
      tx.pure.u64(now),
      tx.pure.vector('u8', sealEncryptedBytes),
      tx.pure.vector('u8', Buffer.from(enclaveSignature, 'hex')),
      tx.object('0x6'),
    ],
  });

  // Execute the transaction
  const result = await suiClient.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx,
    options: {
      showEffects: true,
      showObjectChanges: true,
    },
  });

  console.log('Set master key transaction executed:', result.digest);

  // Check if transaction was successful
  if (result.effects?.status?.status !== 'success') {
    console.error('Transaction failed with status:', result.effects?.status);
    if (result.effects?.status?.error) {
      console.error('Error details:', result.effects.status.error);
    }
    throw new Error(
      `Set master key transaction ${result.digest} failed: ${result.effects?.status?.error || 'Unknown error'}`,
    );
  }
}

/**
 * Generate and store a new encrypted master key
 * This is used on first startup when no master key exists
 */
export async function generateAndStoreMasterKey() {
  // Generate a new master key
  const masterKey = crypto.randomBytes(32);

  // Encrypt the master key using Seal
  const { encryptedKey } = await encryptMasterKey(masterKey);

  // Store on kms module on SUI
  await storeMasterKey(encryptedKey);

  currentMasterKey = {
    masterKey: masterKey.toString('hex'),
    masterKeyBuffer: masterKey,
    encryptedKey: encryptedKey,
  };

  return currentMasterKey;
}

/**
 * Retrieve and decrypt a master key from the database
 * This is used on startup to restore the master key
 */
export async function retrieveAndDecryptMasterKey() {
  const record = await retrieveMasterKey();

  if (!record) {
    return null;
  }

  const decryptedKey = await decryptMasterKey(record.encrypted_key);

  // Store in memory
  currentMasterKey = {
    masterKey: decryptedKey.toString('hex'),
    masterKeyBuffer: decryptedKey,
    encryptedKey: record.encrypted_key,
  };

  return currentMasterKey;
}

/**
 * Initialize master key on enclave startup
 * Either retrieves existing key or generates a new one
 * Also handles rotation if server object IDs have changed
 */
export async function initializeMasterKey() {
  const currentServerConfigs = configManager.getSealConfig().server_configs;

  // Check if key exists
  const record = await retrieveMasterKey();

  if (!record) {
    // No existing key, generate new one
    console.log('Generating new master key.');
    const newKey = await generateAndStoreMasterKey();
    currentMasterKey = newKey;
    return newKey;
  }

  // Decrypt the master key
  const decryptedKey = await decryptMasterKey(record.encrypted_key);

  // Check if server configs have changed (compare object IDs only)
  const storedServerConfigs = record.server_configs;
  const serverConfigsChanged =
    storedServerConfigs.length !== currentServerConfigs.length ||
    storedServerConfigs.some(
      (config, index) =>
        config.objectId.toLowerCase() !==
        currentServerConfigs[index]?.objectId.toLowerCase(),
    );

  if (serverConfigsChanged) {
    console.log('Server configs have changed, rotating master key...');
    console.log(
      'Old server configs:',
      storedServerConfigs.map((c) => c.objectId),
    );
    console.log(
      'New server configs:',
      currentServerConfigs.map((c) => c.objectId),
    );

    // Re-encrypt with new servers (verifies availability)
    const { encryptedKey } = await encryptMasterKey(decryptedKey);

    // Store the re-encrypted key
    await storeMasterKey(encryptedKey);

    currentMasterKey = {
      masterKey: decryptedKey.toString('hex'),
      masterKeyBuffer: decryptedKey,
      encryptedKey,
    };

    console.log('Master key rotated successfully.');
    return currentMasterKey;
  }

  // Server configs haven't changed
  console.log('Server configs unchanged, master key restored.');
  currentMasterKey = {
    masterKey: decryptedKey.toString('hex'),
    masterKeyBuffer: decryptedKey,
    encryptedKey: record.encrypted_key,
  };

  return currentMasterKey;
}
