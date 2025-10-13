import crypto from 'node:crypto';
import { bcs } from '@mysten/bcs';
import { SealClient, SessionKey } from '@mysten/seal';
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
 */
export function createSealClient(): {
  client: SealClient;
  suiClient: SuiClient;
  config: ReturnType<typeof configManager.getSealConfig>;
} {
  const sealConfig = configManager.getSealConfig();
  const { sui_network: suiNetwork, server_object_ids: serverObjectIds } =
    sealConfig;

  const suiClient = new SuiClient({
    url: getFullnodeUrl(suiNetwork as 'testnet' | 'mainnet'),
  });

  // Use server object IDs from config
  if (!serverObjectIds || serverObjectIds.length === 0) {
    throw new Error(
      'No server object IDs configured. Please add server_object_ids to your config file.',
    );
  }

  const client = new SealClient({
    suiClient,
    serverConfigs: serverObjectIds.map((id) => ({
      objectId: id,
      weight: 1,
    })),
    verifyKeyServers: false,
  });

  return { client, suiClient, config: sealConfig };
}

/**
 * Encrypts a master key using Seal
 */
export async function encryptMasterKey(masterKey: Buffer): Promise<{
  encryptedKey: string;
}> {
  const { client, config } = createSealClient();

  if (!config.enclave_object_id) {
    throw new Error('Enclave not registered - cannot encrypt master key');
  }

  const { encryptedObject: encryptedBytes } = await client.encrypt({
    threshold: 3,
    packageId: config.kms_package_id,
    id: KEY_ID.toString('hex'),
    data: masterKey,
  });

  return {
    encryptedKey: Buffer.from(encryptedBytes).toString('hex'),
  };
}

/**
 * Decrypts a master key using Seal with enclave attestation
 * Always uses a random ephemeral Sui account for signing
 */
export async function decryptMasterKey(
  encryptedKeyHex: string,
): Promise<Buffer> {
  const { client, suiClient, config } = createSealClient();
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

  const encryptedBytes = Buffer.from(encryptedKeyHex, 'hex');

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

  const decryptedBytes = await client.decrypt({
    data: encryptedBytes,
    sessionKey,
    txBytes,
  });

  return Buffer.from(decryptedBytes);
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
  const {
    sui_network: suiNetwork,
    encrypted_master_key_object_id,
    sui_secret_key,
  } = configManager.getSealConfig();
  const sui_sk = Buffer.from(
    sui_secret_key.startsWith('0x')
      ? sui_secret_key.substring(2)
      : sui_secret_key,
    'hex',
  );
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
    iv: number[];
    tag: number[];
    version: string;
    updated_at: string;
  };
  if (Number(fields.version) < 1) {
    return null;
  }
  const encrypted_key = decryptData(
    Buffer.from(fields.encrypted_key),
    sui_sk,
    Buffer.from(fields.iv),
    Buffer.from(fields.tag),
  ).toString('hex');
  return {
    encrypted_key,
    version: Number(fields.version),
    updated_at: Number(fields.updated_at),
  };
}

async function storeMasterKey(encryptedKey: string) {
  const {
    module_name: moduleName,
    kms_package_id: kmsPackageId,
    encrypted_master_key_object_id,
    sui_secret_key: suiSecretKey,
    sui_network: suiNetwork,
    enclave_endpoint: enclaveEndpoint,
  } = configManager.getSealConfig();
  const enclaveObjectId = configManager.getEnclaveObjectId();
  if (enclaveObjectId == null) {
    throw new Error('Enclave not registered - cannot store master key');
  }
  const sui_sk = Buffer.from(
    suiSecretKey.startsWith('0x') ? suiSecretKey.substring(2) : suiSecretKey,
    'hex',
  );
  const double_encrypted_master_key = encryptData(
    Buffer.from(encryptedKey, 'hex'),
    sui_sk,
  );

  const now = Date.now();

  const intent = bcs
    .struct('Intent', {
      intent: bcs.u8(),
      timestamp_ms: bcs.u64(),
      data: bcs.struct('SetMasterKeyRequest', {
        encrypted_key: bcs.byteVector(),
        iv: bcs.byteVector(),
        tag: bcs.byteVector(),
      }),
    })
    .serialize({
      intent: SET_MASTER_KEY_INTENT,
      timestamp_ms: now,
      data: {
        encrypted_key: double_encrypted_master_key.encrypted,
        iv: double_encrypted_master_key.iv,
        tag: double_encrypted_master_key.authTag,
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
  const keypair = Ed25519Keypair.fromSecretKey(sui_sk);

  // Build the transaction
  const tx = new Transaction();

  // Register enclave
  tx.moveCall({
    target: `${kmsPackageId}::${moduleName}::set_master_key`,
    typeArguments: [],
    arguments: [
      tx.object(encrypted_master_key_object_id),
      tx.object(enclaveObjectId),
      tx.pure.u64(now),
      tx.pure.vector('u8', double_encrypted_master_key.encrypted),
      tx.pure.vector('u8', double_encrypted_master_key.iv),
      tx.pure.vector('u8', double_encrypted_master_key.authTag),
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
 */
export async function initializeMasterKey() {
  // Check if key exists
  const existingKey = await retrieveAndDecryptMasterKey();
  if (existingKey) {
    console.log('Master key restored.');
    return existingKey;
  }

  // Generate new key
  console.log('Generating new master key.');
  const newKey = await generateAndStoreMasterKey();
  return newKey;
}
