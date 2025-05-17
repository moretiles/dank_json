# clang compiles, lints, and does static analysis
# make/cmake for builds
# ragel/graphviz if I want to do parsing
# sudo because we need unlimited power
# ctags because I forgot to install it on the host
# pwndbg for debugging
# binutils provides gprof for performance testing
# afl++ for dynamic analysis

FROM docker.io/archlinux/archlinux
RUN pacman -Syyu --noconfirm clang make cmake ragel graphviz sudo ctags pwndbg binutils afl++ && groupadd -g 1000 dev && useradd -u 1000 -g dev -m dev && (tee -a /etc/sudoers <<< 'dev ALL=(ALL:ALL) NOPASSWD: ALL') && (tee -a /home/dev/.gdbinit <<< 'source /usr/share/pwndbg/gdbinit.py') && (tee -a /home/dev/.gdbinit <<< 'set disassembly-flavor intel')
USER dev
ENV CC=clang CXX=clang++

# Issue with debian container, msan and tsan fail with gcc/clang
#FROM mcr.microsoft.com/devcontainers/base:debian
#RUN apt-get update -y && apt-get -y install clang make cmake build-essential ragel graphviz locales && rm -rf /var/lib/apt/lists/*
