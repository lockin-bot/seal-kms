#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"
# Load PCRs from out/nitro.pcrs
PCR_FILE="$DIR/out/nitro.pcrs"

if [ ! -f "$PCR_FILE" ]; then
    echo "Error: $PCR_FILE not found"
    exit 1
fi

# Extract hex values for each PCR
PCR0=$(grep "PCR0" "$PCR_FILE" | awk '{print $1}')
PCR1=$(grep "PCR1" "$PCR_FILE" | awk '{print $1}')
PCR2=$(grep "PCR2" "$PCR_FILE" | awk '{print $1}')

# Convert hex strings to Rust-style byte arrays
PCR0_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$PCR0")
PCR1_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$PCR1")
PCR2_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$PCR2")

# The name for the enclave config (as a hex-encoded string)
NAME="\"kms-enclave-config\""

# Execute sui client command with the correct parameters
# Using the KMS module structure from kms.move
sui client ptb \
    --move-call "${ENCLAVE_PACKAGE_ID}::enclave::create_enclave_config<${KMS_PACKAGE_ID}::kms::KMS>" "@${CAP_OBJECT_ID}" ${NAME} vector[${PCR0_ARRAY}] vector[${PCR1_ARRAY}] vector[${PCR2_ARRAY}] "@${ENCLAVE_REGISTER}"
