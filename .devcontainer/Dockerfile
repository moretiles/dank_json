FROM docker.io/library/debian
RUN apt-get update -y && \
        apt-get -y install --no-install-recommends tmux screen git vim bash apt-utils curl wget \
        make cmake build-essential gcc g++-multilib ragel locales universal-ctags && \
        useradd -u 1000 -s /bin/bash dev && \
        mkdir -p /home/dev && \
        chown -R dev:dev /home/dev
USER dev
