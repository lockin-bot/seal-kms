# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

# This containerfile uses StageX (https://stagex.tools) images, which provide a
# full source bootstrapped, deterministic, and hermetic build toolchain

FROM stagex/pallet-rust@sha256:6fbc40649978232f16cecbaa9c8bd91d5d750a8293969af54684fc4f2fc80e84 AS pallet-rust
FROM stagex/pallet-nodejs@sha256:b1bdeaec4b377825d5e3bc7431f937b591a1eca2a1669a6827b48bf0cbfcce62 AS pallet-nodejs
FROM stagex/user-eif_build@sha256:0eabf3d09ccf0421bc09fe9e90b656ecc1140155d5358f35de63e2cfd814f4f9 AS user-eif_build
FROM stagex/user-gen_initramfs@sha256:aff0791ee9ccdeed1304b5bb4edb7fc5b7f485e11bccf5e61668001243ada815 AS user-gen_initramfs
FROM stagex/user-cpio@sha256:05701450a186fa1cb5a8287f7fa4d216e610a15d22c2e3e86d70ac3550d9cd3c AS user-cpio

FROM scratch AS base
ENV TARGET=x86_64-unknown-linux-musl
ENV RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=static"
ENV CARGOFLAGS="--locked --no-default-features --release --target ${TARGET}"
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV OPENSSL_STATIC=true

COPY --from=pallet-rust . /
COPY --from=pallet-nodejs . /
COPY --from=user-gen_initramfs . /
COPY --from=user-eif_build . /
COPY --from=user-cpio . /

FROM base AS build-nautilus
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src/system ./src/system
COPY src/aws ./src/aws
COPY src/init ./src/init
COPY src/nautilus-server/Cargo.toml ./src/nautilus-server/Cargo.toml
COPY src/host-proxy/Cargo.toml ./src/host-proxy/Cargo.toml
RUN cargo -V

RUN mkdir src/nautilus-server/src && echo 'fn main() {}' > src/nautilus-server/src/main.rs && \
    mkdir src/host-proxy/src && echo 'fn main() {}' > src/host-proxy/src/main.rs && \
    cargo build --locked --no-default-features --release --target ${TARGET} && \
    rm -rf src/nautilus-server

COPY src/nautilus-server ./src/nautilus-server
RUN cargo build --bin nautilus-server --locked --no-default-features --release --target ${TARGET}
RUN ls -lh /target/${TARGET}/release

FROM base AS build
WORKDIR /
RUN node -v && npm -v && npm i -g yarn@1.22.22
COPY tsconfig.json ./
COPY package.json ./
COPY yarn.lock ./
COPY app ./app
RUN rm -rf node_modules && yarn install --prod --frozen-lockfile && \
    mkdir -p dist && mv node_modules dist/ && \
    yarn install --frozen-lockfile && \
    yarn build

WORKDIR /build_cpio
ENV KBUILD_BUILD_TIMESTAMP=1
RUN ls -l && mkdir initramfs/
ADD https://github.com/aws/aws-nitro-enclaves-cli/raw/9ba2468fa96813e83e8dd222d4b25d4e1a8070ad/blobs/x86_64/bzImage /bzImage
ADD https://github.com/aws/aws-nitro-enclaves-cli/raw/9ba2468fa96813e83e8dd222d4b25d4e1a8070ad/blobs/x86_64/bzImage.config /bzImage.config
ADD https://github.com/aws/aws-nitro-enclaves-cli/raw/9ba2468fa96813e83e8dd222d4b25d4e1a8070ad/blobs/x86_64/nsm.ko initramfs/nsm.ko
COPY --from=pallet-nodejs . initramfs
COPY app/entrypoint.sh initramfs/usr/local/bin/entrypoint.sh
COPY --from=build-nautilus /target/${TARGET}/release/init initramfs/init
COPY --from=build-nautilus /target/${TARGET}/release/nautilus-server initramfs/usr/local/bin/nautilus-server
RUN mv /dist initramfs/app && mv /package.json initramfs/package.json

RUN <<-EOF
    set -eux
    cd initramfs
    find . -exec touch -hcd "@0" "{}" +
    find . -print0 \
    | sort -z \
    | cpio \
        --null \
        --create \
        --verbose \
        --reproducible \
        --format=newc \
    | gzip --fast \
    > /build_cpio/rootfs.cpio
EOF

WORKDIR /build_eif
RUN eif_build \
	--kernel /bzImage \
	--kernel_config /bzImage.config \
	--ramdisk /build_cpio/rootfs.cpio \
	--pcrs_output /nitro.pcrs \
	--output /nitro.eif \
	--cmdline 'reboot=k initrd=0x2000000,3228672 root=/dev/ram0 panic=1 pci=off nomodules console=ttyS0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd'

FROM base AS install
WORKDIR /rootfs
COPY --from=build /nitro.eif .
COPY --from=build /nitro.pcrs .
COPY --from=build /build_cpio/rootfs.cpio .

FROM scratch AS package
COPY --from=install /rootfs .
