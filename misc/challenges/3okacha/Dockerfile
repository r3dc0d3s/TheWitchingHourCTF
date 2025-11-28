FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat  && useradd -m pwn

WORKDIR /home/pwn

COPY jailed /home/pwn/jailed
COPY flag.txt /home/pwn/flag.txt

RUN chown root:pwn /home/pwn/flag.txt && \
    chown root:pwn /home/pwn/jailed && \
    chmod 440 /home/pwn/flag.txt && \
    chmod 750 /home/pwn/jailed

COPY init.sh /init.sh
RUN chmod +x /init.sh

USER pwn

ENTRYPOINT [ "/init.sh" ]