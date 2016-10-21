#! /usr/bin/ksh
#
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

#
# Copyright 2015, Richard Lowe.
#

cd /tmp;

cleanup() {
    rm /tmp/output.$$
    rm /tmp/expected.$$
}

trap cleanup EXIT

cat > /tmp/expected.$$ <<EOF
^psecflags\(0x[0-9A-F]+, PSF_INHERIT, \{ PROC_SEC_ASLR, 0x0, 0x0, B_FALSE \}\) = 0$
EOF

truss -t psecflags /usr/bin/psecflags -s current,aslr -e ls \
      >/dev/null 2>output.$$

if ! grep -qEf /tmp/expected.$$ /tmp/output.$$; then
    echo "truss: failed"
    echo "output:"
    sed -e 's/^/  /' output.$$
    echo "should match:"
    sed -e 's/^/  /' expected.$$
    exit 1;
fi

exit 0
