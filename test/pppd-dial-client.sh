#!/bin/bash

sudo pppd plugin rp-pppoe.so docker0 user "testuser" password "password1234" noipdefault nodefaultroute nopersist noauth password password1234 nodetach nolog logfd 2
