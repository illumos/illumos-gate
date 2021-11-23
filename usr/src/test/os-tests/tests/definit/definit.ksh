#!/usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

typeset dir=$(dirname $0)

typeset tf=$(mktemp)
if [[ -z "$tf" || ! -f "$tf" ]]; then
	print "Could not create temporary file."
	exit 1
fi
trap 'rm -f $tf' EXIT

integer exitval=0

for b in 32 64; do
	typeset bin=definit_test.$b
	print "Testing $bin"
	if ! $dir/$bin $dir/init.data > $tf; then
		print "Failed to run $bin"
		exitval=1
	fi
	if ! diff $tf $dir/init.expected; then
		print "Output from $bin did not match"
		exitval=1
	fi
done

((exitval == 0)) && print "All tests passed successfully"

exit $exitval
