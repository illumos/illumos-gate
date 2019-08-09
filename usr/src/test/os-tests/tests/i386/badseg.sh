#!/bin/bash
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright 2019 Joyent, Inc.
#

#
# badseg intentionally core-dumps. It does a setrlimit(), but we need to
# prevent global core dumps too: we'll do this by blocking the path for
# badseg_exec, but let other processes core dump still just in case.
#

set -e
set -x

old_enabled=$(/usr/bin/svcprop -p config_params/global_enabled coreadm)
old_pattern=$(/usr/bin/svcprop -p config_params/global_pattern coreadm)
old_log=$(/usr/bin/svcprop -p config_params/global_log_enabled coreadm)

mkfile 1m /var/cores/badseg_exec
coreadm -e global -d log -g /var/cores/%f/%p
# let it settle
sleep 3

$(dirname $0)/badseg_exec || true

coreadm -g "$old_pattern"

if [[ "$old_enabled" = "true" ]]; then
       coreadm -e global
fi

if [[ "$old_log" = "true" ]]; then
       coreadm -e log
fi

rm -f /var/cores/badseg_exec
