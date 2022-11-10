#!/usr/bin/ksh
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
# Copyright 2022 Oxide Computer Company
#

#
# This test acts as a series of regression tests in DTrace around
# printing bitfields that are byte sized at non-byte aligned offsets and
# around printing fields that are less than a byte in size, but due to their
# offset, cross a byte boundary (e.g. a 5-bit bitfield that starts at
# bit 6).
#
# The DTrace implementation has two different general paths for this:
#
#  o The D compiler compiling a dereference into DIF code to be executed
#    in probe context to extract a bitfield value.
#  o The print() action which grabs the larger chunk of memory and then
#    processes it all in userland.
#

if [ $# != 1 ]; then
        echo expected one argument: '<'dtrace-path'>'
        exit 2
fi

dtrace=$1
exe="tst.bitfields.exe"

elfdump "./$exe" | grep -q '.SUNW_ctf'
if (( $? != 0 )); then
	echo "CTF does not exist in $exe, that's a bug" >&2
	exit 1
fi

$dtrace -qs /dev/stdin -c "./$exe 0xe417 0x9391d7db" <<EOF
pid\$target::mumble:entry
{
	print(*args[1]);
	printf("\n");
	print(*args[2]);
	printf("\n");
	trace(args[2]->b);
	printf("\n0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", args[2]->a, args[2]->b,
	    args[2]->c, args[2]->d, args[2]->e, args[2]->f);
	trace(args[1]->i);
	printf("\n0x%x 0x%x 0x%x 0x%x\n", args[1]->g, args[1]->h, args[1]->i,
	    args[1]->j);
}
EOF

exit $rc
