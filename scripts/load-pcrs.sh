#!/bin/bash
set -e

ATTESTATION_HEX=$(curl -s $ENCLAVE_ENDPOINT/get_attestation | jq -r '.attestation')
ATTESTATION_ARRAY=$(node -e 'console.log(Array.from(Buffer.from(process.argv[1], "hex")).map(v => `${v}u8`).join(", "))' "$ATTESTATION_HEX")

# Execute sui client command with the converted array and provided arguments
sui client ptb --dev-inspect --assign v "vector[$ATTESTATION_ARRAY]" \
    --move-call "0x2::nitro_attestation::load_nitro_attestation" v @0x6 \
    --assign result \
    --move-call "0x2::nitro_attestation::pcrs" result
