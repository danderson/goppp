#!/bin/bash

pppoe-server -C test-pppoe-access-concentrator -L 10.67.15.1 -p /etc/ppp/ipaddress_pool -I eth0 -r -F
