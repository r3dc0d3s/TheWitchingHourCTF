#!/bin/sh

docker rm -f broken_company 2>/dev/null
docker build -t broken_company .
docker run --privileged --rm -it -d --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE --cap-add=CAP_SYS_CHROOT --security-opt seccomp=unconfined -p 1333:5000 --name broken_company broken_company:latest
