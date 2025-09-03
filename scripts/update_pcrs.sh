#!/bin/bash
PCR0_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$PCR0")
PCR1_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$PCR1")
PCR2_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$PCR2")

# Execute sui client command with the converted array and provided arguments
sui client ptb \
    --move-call "${ENCLAVE_PACKAGE_ID}::enclave::update_pcrs<${KMS_PACKAGE_ID}::${MODULE_NAME}::${OTW_NAME}>" @${ENCLAVE_CONFIG_OBJECT_ID} @${CAP_OBJECT_ID} vector[${PCR0_ARRAY}] vector[${PCR1_ARRAY}] vector[${PCR2_ARRAY}]
