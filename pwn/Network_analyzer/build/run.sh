#!/bin/sh

docker rm -f network_analyzer 2>/dev/null
docker build -t network_analyzer .
docker run --privileged --rm -it -d --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE --cap-add=CAP_SYS_CHROOT --security-opt seccomp=unconfined -p 1334:5000 --name network_analyzer network_analyzer:latest
