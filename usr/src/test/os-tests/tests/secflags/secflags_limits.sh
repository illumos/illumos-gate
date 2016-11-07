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

mkdir /tmp/secflags-test.$$
cd /tmp/secflags-test.$$

cleanup() {
    kill $pid >/dev/null 2>&1
    cd /
    rm -fr /tmp/secflags-test.$$
}

trap cleanup EXIT

# Check that lower implies setting of inheritable
echo "Setting lower also adds to inheritable" 
/usr/bin/psecflags -s L=aslr $$

cat > expected <<EOF
	I:	aslr
EOF
/usr/bin/psecflags $$ | grep 'I:' > output

diff -u expected output || exit 1

echo "Setting in lower cannot be removed from inheritable"
/usr/bin/psecflags -s I=current,-aslr $$ 2>/dev/null && exit 1

echo "Setting in lower cannot be removed"
/usr/bin/psecflags -s L=current,-aslr $$ 2>/dev/null && exit 1


echo "Setting in lower cannot be removed from upper"
/usr/bin/psecflags -s U=current,-aslr $$ 2>/devlnull && exit 1

/usr/bin/psecflags -s U=current,-noexecstack $$

echo "Setting in default cannot exceed upper"
/usr/bin/psecflags -s I=noexecstack $$ 2>/dev/null && exit 1

echo "Setting cannot ever be added to upper"
/usr/bin/psecflags -s U=current,+noexecstack $$ 2>/dev/null && exit 1

exit 0


