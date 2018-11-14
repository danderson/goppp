FROM debian:testing

RUN apt -y update && \
    DEBIAN_FRONTEND=noninteractive apt -y install ppp pppoe tcpdump
COPY * /etc/ppp/
RUN chmod 600 /etc/ppp/chap-secrets
CMD /etc/ppp/run-pppoe-server.sh

# Execute container with: docker run --cap-add=NET_ADMIN --device=/dev/ppp
