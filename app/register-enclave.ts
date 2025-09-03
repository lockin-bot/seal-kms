import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { got } from 'got-cjs';
import { configManager } from './config.js';

export async function registerEnclave(): Promise<string> {
  const sealConfig = configManager.getSealConfig();
  const {
    enclave_package_id: enclavePackageId,
    module_name: moduleName,
    otw_name: otwName,
    kms_package_id: kmsPackageId,
    enclave_endpoint: enclaveEndpoint,
    enclave_config_object_id: enclaveConfigObjectId,
    sui_secret_key: suiSecretKey,
    sui_network: suiNetwork,
  } = sealConfig;

  console.log('Registering enclave with configuration:', {
    enclavePackageId,
    moduleName,
    enclaveConfigObjectId,
    suiNetwork,
  });

  // Get attestation from enclave
  const attestationResponse = await got
    .get(`${enclaveEndpoint}/get_attestation`, {
      timeout: { request: 10000 },
      retry: { limit: 2 },
    })
    .json<{ attestation: string }>();

  const attestationHex = attestationResponse.attestation;
  console.log('Got attestation from enclave');

  // Convert attestation hex to byte array
  const attestationBytes = Array.from(Buffer.from(attestationHex, 'hex'));

  // Initialize Sui client
  const suiClient = new SuiClient({
    url: getFullnodeUrl(suiNetwork as 'testnet' | 'mainnet'),
  });

  // Create keypair from secret key
  const keypair = Ed25519Keypair.fromSecretKey(
    Buffer.from(
      suiSecretKey.startsWith('0x') ? suiSecretKey.substring(2) : suiSecretKey,
      'hex',
    ),
  );
  const address = keypair.getPublicKey().toSuiAddress();
  console.log('Using address:', address);

  // Build the transaction
  const tx = new Transaction();

  // Load nitro attestation
  const attestationArg = tx.pure.vector('u8', attestationBytes);
  const [attestation] = tx.moveCall({
    target: '0x2::nitro_attestation::load_nitro_attestation',
    arguments: [attestationArg, tx.object('0x6')],
  });

  // Register enclave
  tx.moveCall({
    target: `${enclavePackageId}::enclave::register_enclave`,
    typeArguments: [`${kmsPackageId}::${moduleName}::${otwName}`],
    arguments: [tx.object(enclaveConfigObjectId), attestation],
  });

  try {
    // Execute the transaction
    const result = await suiClient.signAndExecuteTransaction({
      signer: keypair,
      transaction: tx,
      options: {
        showEffects: true,
        showObjectChanges: true,
      },
    });

    console.log('Transaction executed:', result.digest);

    // Check if transaction was successful
    if (result.effects?.status?.status !== 'success') {
      console.error('Transaction failed with status:', result.effects?.status);
      if (result.effects?.status?.error) {
        console.error('Error details:', result.effects.status.error);
      }
      throw new Error(
        `Transaction failed: ${result.effects?.status?.error || 'Unknown error'}`,
      );
    }

    if (result.objectChanges != null) {
      console.log('Object changes:');
      for (const change of result.objectChanges) {
        console.log(JSON.stringify(change, null, 2));
      }
    }

    // Find the created enclave object ID
    const createdObject = result.objectChanges?.find((change) => {
      if (change.type === 'created' && change.objectType) {
        console.log(`Checking object type: ${change.objectType}`);
        // Check for both possible formats
        return (
          change.objectType.includes('::enclave::Enclave') ||
          change.objectType.includes('enclave::enclave::Enclave')
        );
      }
      return false;
    });

    if (!createdObject || createdObject.type !== 'created') {
      console.error('No enclave object found in transaction results.');
      console.error('Looking for object type containing "::enclave::Enclave"');
      if (result.objectChanges) {
        console.error(
          'Available object changes:',
          result.objectChanges.map((c) => ({
            type: c.type,
            objectType: 'objectType' in c ? c.objectType : undefined,
          })),
        );
      }
      throw new Error('Failed to find created enclave object');
    }

    const enclaveObjectId = createdObject.objectId;
    console.log('Enclave registered successfully with ID:', enclaveObjectId);

    // Store the enclave object ID in config manager
    configManager.setEnclaveObjectId(enclaveObjectId);

    return enclaveObjectId;
  } catch (error) {
    console.error('Failed to register enclave:', error);
    throw new Error(
      `Enclave registration failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
    );
  }
}

export async function ensureEnclaveRegistered(): Promise<string> {
  // Check if enclave is already registered
  const existingId = configManager.getEnclaveObjectId();
  if (existingId) {
    console.log('Enclave already registered with ID:', existingId);
    return existingId;
  }

  // Register the enclave
  return registerEnclave();
}
