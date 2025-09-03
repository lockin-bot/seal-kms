import crypto from 'node:crypto';
import { bcs } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { configManager } from './config.js';

// Define the BCS schema for NitroAttestationDocument
const AttestationDocumentSchema = bcs.struct('NitroAttestationDocument', {
  module_id: bcs.vector(bcs.u8()),
  timestamp: bcs.u64(),
  digest: bcs.vector(bcs.u8()),
  pcrs: bcs.vector(
    bcs.struct('PCREntry', {
      index: bcs.u8(),
      value: bcs.vector(bcs.u8()),
    }),
  ),
  public_key: bcs.option(bcs.vector(bcs.u8())),
  user_data: bcs.option(bcs.vector(bcs.u8())),
  nonce: bcs.option(bcs.vector(bcs.u8())),
});

/**
 * NitroAttestationDocument structure from Sui's nitro_attestation module
 */
interface NitroAttestationDocument {
  module_id: number[];
  timestamp: string;
  digest: number[];
  pcrs: {
    index: number;
    value: number[];
  }[];
  public_key: number[] | null;
  user_data: number[] | null;
  nonce: number[] | null;
}

/**
 * Validates a remote attestation document using Sui's nitro_attestation module
 * and extracts the public key from the document
 */
export async function validateRemoteAttestation(
  attestationHex: string,
  enclaveConfigObjectId: string,
): Promise<{
  isValid: boolean;
  publicKey?: Buffer;
  pcrs?: { pcr0: Buffer; pcr1: Buffer; pcr2: Buffer };
  enclaveType?: string;
  error?: string;
}> {
  try {
    const { sui_network: suiNetwork } = configManager.getSealConfig();
    const suiClient = new SuiClient({
      url: getFullnodeUrl(suiNetwork as 'testnet' | 'mainnet'),
    });

    // Build a transaction to load and parse the attestation document
    const tx = new Transaction();

    // Convert attestation hex to byte array
    const attestationBytes = Array.from(Buffer.from(attestationHex, 'hex'));

    // Load the attestation document using Sui's nitro_attestation module
    const attestationArg = tx.pure.vector('u8', attestationBytes);
    tx.moveCall({
      target: '0x2::nitro_attestation::load_nitro_attestation',
      arguments: [attestationArg, tx.object('0x6')], // 0x6 is the clock object
    });

    // Execute the transaction in dev-inspect mode to get the attestation data
    const sender =
      '0x0000000000000000000000000000000000000000000000000000000000000002';
    const result = await suiClient.devInspectTransactionBlock({
      transactionBlock: tx,
      sender,
    });

    if (result.effects.status.status !== 'success') {
      return {
        isValid: false,
        error: `Failed to load attestation: ${result.effects.status.error || 'Unknown error'}`,
      };
    }

    // Extract the attestation document from the return values
    // The load_nitro_attestation function returns a NitroAttestationDocument
    let attestationDoc: NitroAttestationDocument | null = null;

    if (result.results && result.results.length > 0) {
      // The first result should be our attestation document
      const firstResult = result.results[0];
      if (firstResult.returnValues && firstResult.returnValues.length > 0) {
        const returnValue = firstResult.returnValues[0];
        // Decode the BCS-encoded attestation document
        try {
          // Decode the attestation document
          attestationDoc = AttestationDocumentSchema.parse(
            Buffer.from(returnValue[0]),
          );
        } catch (e) {
          console.error('Failed to decode attestation document:', e);
        }
      }
    }

    if (!attestationDoc) {
      return {
        isValid: false,
        error: 'Failed to extract attestation document from transaction result',
      };
    }

    // Extract public key from the attestation document
    let publicKey: Buffer | undefined;
    if (attestationDoc.public_key) {
      publicKey = Buffer.from(attestationDoc.public_key);
    }

    if (!publicKey) {
      return {
        isValid: false,
        error: 'No public key found in attestation document',
      };
    }

    // Extract PCRs from the attestation document
    let pcr0: Buffer | undefined;
    let pcr1: Buffer | undefined;
    let pcr2: Buffer | undefined;

    for (const pcrEntry of attestationDoc.pcrs) {
      switch (pcrEntry.index) {
        case 0:
          pcr0 = Buffer.from(pcrEntry.value);
          break;
        case 1:
          pcr1 = Buffer.from(pcrEntry.value);
          break;
        case 2:
          pcr2 = Buffer.from(pcrEntry.value);
          break;
      }
    }

    if (!pcr0 || !pcr1 || !pcr2) {
      return {
        isValid: false,
        error: 'Missing required PCR values in attestation document',
      };
    }

    // Fetch the enclave config to compare PCRs
    const configObject = await suiClient.getObject({
      id: enclaveConfigObjectId,
      options: {
        showContent: true,
      },
    });

    if (
      !configObject.data?.content ||
      configObject.data.content.dataType !== 'moveObject'
    ) {
      return {
        isValid: false,
        error: 'Invalid enclave config object',
      };
    }

    // Extract the enclave type from the object type
    // Format is typically: package_id::module::EnclaveConfig<T>
    const enclaveType = configObject.data.content.type;

    const fields = configObject.data.content.fields as {
      pcrs: {
        type: string;
        fields: {
          pos0: number[];
          pos1: number[];
          pos2: number[];
        };
      };
    };

    const expectedPcr0 = Buffer.from(fields.pcrs.fields.pos0);
    const expectedPcr1 = Buffer.from(fields.pcrs.fields.pos1);
    const expectedPcr2 = Buffer.from(fields.pcrs.fields.pos2);

    // Compare PCRs
    const pcrsMatch =
      expectedPcr0.equals(pcr0) &&
      expectedPcr1.equals(pcr1) &&
      expectedPcr2.equals(pcr2);

    if (!pcrsMatch) {
      return {
        isValid: false,
        error: 'PCR values do not match the expected configuration',
        publicKey,
        pcrs: { pcr0, pcr1, pcr2 },
        enclaveType,
      };
    }

    return {
      isValid: true,
      publicKey,
      pcrs: { pcr0, pcr1, pcr2 },
      enclaveType,
    };
  } catch (error) {
    console.error('Attestation validation error:', error);
    return {
      isValid: false,
      error:
        error instanceof Error ? error.message : 'Unknown validation error',
    };
  }
}

/**
 * Verifies an Ed25519 signature
 */
export function verifyEd25519Signature(
  message: Buffer,
  signature: Buffer,
  publicKey: Buffer,
): boolean {
  try {
    // If this is a raw 32-byte Ed25519 public key, we need to wrap it properly
    let keyObject: crypto.KeyObject;

    if (publicKey.length === 32) {
      // Raw Ed25519 public key - need to add SPKI wrapper
      // SPKI prefix for Ed25519: 302a300506032b6570032100
      const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
      const spkiPublicKey = Buffer.concat([spkiPrefix, publicKey]);

      keyObject = crypto.createPublicKey({
        key: spkiPublicKey,
        format: 'der',
        type: 'spki',
      });
    } else {
      // Already in SPKI format
      keyObject = crypto.createPublicKey({
        key: publicKey,
        format: 'der',
        type: 'spki',
      });
    }

    return crypto.verify(null, message, keyObject, signature);
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}
