#!/bin/bash
socat -T60 TCP-LISTEN:${JAILED_PORT},reuseaddr,fork EXEC:/home/pwn/jailed,pty,stderr