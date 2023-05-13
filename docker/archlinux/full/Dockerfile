ARG acct
ARG repo
ARG dist_name
ARG dist_version
ARG machine

FROM ${acct}/${repo}:${dist_name}-${dist_version}-base-${machine}

ENV packages="\
freetype2 \
graphicsmagick \
libpng \
ocl-icd \
opencl-headers \
opencl-mesa \
spirv-llvm-translator \
"

ENV packages_dev="\
${packages_dev} \
vim \
"

RUN true \
&& pacman -Sy --noconfirm ${packages} \
&& ln -s /usr/share/clc /usr/lib/clc \
&& true
