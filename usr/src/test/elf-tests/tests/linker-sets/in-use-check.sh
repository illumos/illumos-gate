#!/usr/bin/ksh
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
# Copyright 2018, Richard Lowe.
#

# Test that existing definitions of the start/stop symbols are reported
# as conflicting with internal symbols.

tmpdir=/tmp/test.$$
mkdir $tmpdir
cd $tmpdir

cleanup() {
    cd /
    rm -fr $tmpdir
}

trap 'cleanup' EXIT

cat > broken.c <<EOF
char foo[1024] __attribute__((section("set_foo")));
void *__start_set_foo;

int
main()
{
	return (0);
}
EOF

# We expect any alternate linker to be in LD_ALTEXEC for us already
gcc -o broken broken.c -Wall -Wextra -Wl,-zfatal-warnings > in-use.$$.out 2>&1
if (( $? == 0 )); then
    print -u2 "use of a reserved symbol didn't fail"
    exit 1;
fi

grep -q "^ld: warning: reserved symbol '__start_set_foo' already defined in file" in-use.$$.out
if (( $? != 0 )); then
    print -u2 "use of a reserved symbol failed for the wrong reason"
    exit 1;
fi
