FROM docker.io/library/debian:unstable
RUN apt-get update -y && \
        apt-get -y install --no-install-recommends tmux screen git vim bash apt-utils curl wget procps \
        make cmake build-essential gcc g++-multilib ragel locales universal-ctags && \
        useradd -u 1000 -s /bin/bash dev && \
        mkdir -p /home/dev && \
        chown -R dev:dev /home/dev
USER dev
