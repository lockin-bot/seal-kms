#!/bin/bash

# Set default PCR values for debug mode (all zeros)
ZERO_PCR="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
PCR0_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$ZERO_PCR")
PCR1_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$ZERO_PCR")
PCR2_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$ZERO_PCR")

# The name for the enclave config (as a hex-encoded string)
NAME="\"debug-enclave\""

# Execute sui client command with the correct parameters
# Using the KMS module structure from kms.move
sui client ptb \
    --move-call "${ENCLAVE_PACKAGE_ID}::enclave::create_enclave_config<${KMS_PACKAGE_ID}::kms::KMS>" "@${CAP_OBJECT_ID}" ${NAME} vector[${PCR0_ARRAY}] vector[${PCR1_ARRAY}] vector[${PCR2_ARRAY}] "@${ENCLAVE_REGISTER}"
