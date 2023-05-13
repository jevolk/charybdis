ARG dist_name archlinux
ARG dist_version latest

FROM --platform=$TARGETPLATFORM ${dist_name}:${dist_version}

ENV packages="\
boost \
boost-libs \
icu \
libatomic_ops \
file \
libsodium \
lz4 \
openssl \
rocksdb \
zstd \
"

ENV packages_dev="\
"

RUN true \
&& pacman -Sy --noconfirm ${packages} \
&& true
