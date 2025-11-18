import crypto from 'node:crypto';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { configManager } from './config.js';
import {
  type EnclaveKeyRequest,
  processEnclaveKeyRequest,
} from './enclave-key-service.js';
import {
  decryptDataHex,
  encryptData,
  getCurrentMasterKey,
  initializeMasterKey,
  isMasterKeyInitialized,
} from './master-key.js';
import { ensureEnclaveRegistered } from './register-enclave.js';

console.log(`Using node version ${process.version}`);

const app = express();
const proxyHandler = createProxyMiddleware({
  target: 'http://127.0.0.1:3000',
});
app.get('/health_check', proxyHandler);
app.get('/get_attestation', proxyHandler);

app.use(express.json());
app.get('/', (_, res) => {
  res.send('Hello from seal-kms!');
});

// Additional debug endpoints that explicitly use the startup master key
app.get('/debug/master-key', async (_, res) => {
  try {
    if (!isMasterKeyInitialized()) {
      return res.status(500).json({
        success: false,
        error: 'Master key not initialized',
      });
    }
    const startupKey = getCurrentMasterKey();

    const keypair = Ed25519Keypair.fromSecretKey(startupKey.masterKey);

    res.json({
      success: true,
      data: {
        masterPublicKey: keypair.getPublicKey().toBase64(),
      },
    });
  } catch (error) {
    console.error('Error getting startup master key:', error);
    res.status(500).json({
      success: false,
      error:
        error instanceof Error ? error.message : 'Failed to get startup key',
    });
  }
});

app.post('/debug/master-key/encrypt', async (req, res) => {
  try {
    if (!isMasterKeyInitialized()) {
      return res.status(500).json({
        success: false,
        error: 'Master key not initialized',
      });
    }

    const { dataHex } = req.body;

    if (!dataHex) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameter: dataHex',
      });
    }

    const { masterKey } = getCurrentMasterKey();
    const dataBuffer = Buffer.from(dataHex, 'hex');
    const keyBuffer = Buffer.from(masterKey, 'hex');

    const { encrypted, iv, authTag } = encryptData(dataBuffer, keyBuffer);

    res.json({
      success: true,
      data: {
        encryptedDataHex: encrypted,
        ivHex: iv,
        authTagHex: authTag,
        note: 'Encrypted with startup master key',
      },
    });
  } catch (error) {
    console.error('Error encrypting with startup key:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Encryption failed',
    });
  }
});

app.post('/debug/master-key/decrypt', async (req, res) => {
  try {
    if (!isMasterKeyInitialized()) {
      return res.status(500).json({
        success: false,
        error: 'Master key not initialized',
      });
    }

    const { encryptedDataHex, ivHex, authTagHex } = req.body;

    if (!encryptedDataHex || !ivHex || !authTagHex) {
      return res.status(400).json({
        success: false,
        error:
          'Missing required parameters: encryptedDataHex, ivHex, and authTagHex',
      });
    }

    const { masterKey } = getCurrentMasterKey();

    const decrypted = decryptDataHex(
      encryptedDataHex,
      masterKey,
      ivHex,
      authTagHex,
    );

    res.json({
      success: true,
      data: {
        decryptedHex: decrypted.toString('hex'),
        note: 'Decrypted with startup master key',
      },
    });
  } catch (error) {
    console.error('Error decrypting with startup key:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Decryption failed',
    });
  }
});

// Main API endpoint for client enclaves to request private keys
app.post('/api/request-enclave-key', async (req, res) => {
  try {
    if (!isMasterKeyInitialized()) {
      return res.status(500).json({
        success: false,
        error: 'Master key not initialized',
      });
    }

    const request: EnclaveKeyRequest = req.body;

    // Validate request structure
    if (
      !request.ephemeral_public_key ||
      !request.attestation_document ||
      !request.enclave_config_object_id ||
      !request.timestamp_ms ||
      !request.signature
    ) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameters in request',
        required: [
          'ephemeral_public_key',
          'attestation_document',
          'enclave_config_object_id',
          'timestamp_ms',
          'signature',
        ],
      });
    }

    // Process the request
    const result = await processEnclaveKeyRequest(request);

    if (!result.success) {
      return res.status(400).json({
        success: false,
        error: result.error || 'Failed to process request',
      });
    }

    res.json({
      success: true,
      data: result.data,
    });
  } catch (error) {
    console.error('Error processing enclave key request:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Internal server error',
    });
  }
});

async function startServer() {
  // Load configuration - fail fast if it cannot be loaded
  await configManager.loadConfig();
  console.log('Enclave configuration loaded successfully');

  // Register enclave if not already registered
  try {
    const enclaveObjectId = await ensureEnclaveRegistered();
    console.log('Enclave object ID:', enclaveObjectId);
  } catch (error) {
    console.error('Failed to register enclave:', error);
    console.log(
      'Continuing without enclave registration - some features may not work',
    );
  }

  // Initialize master key on startup
  try {
    const masterKey = await initializeMasterKey();
    const hash = crypto
      .createHash('sha256')
      .update(masterKey.masterKeyBuffer)
      .digest('hex');
    console.log('Master key initialized, key hash: ', hash);
  } catch (error) {
    console.error('Failed to initialize master key:', error);
    console.log(
      'Continuing without master key - encryption features may not work',
    );
  }

  const config = configManager.getConfig();
  console.log('Configuration loaded:', config);

  app.listen(8000, () => {
    console.log('Server running at http://127.0.0.1:8000');
  });
}

startServer().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
