#!/bin/sh

docker rm -f nuclear_warfare 2>/dev/null
docker build -t nuclear_warfare .
docker run --privileged --rm -it -d --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE --cap-add=CAP_SYS_CHROOT --security-opt seccomp=unconfined -p 1335:5000 --name nuclear_warfare nuclear_warfare:latest

