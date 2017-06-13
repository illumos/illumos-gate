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
# Copyright 2016 Joyent, Inc.
#

#
# Add regression tests for illumos#5079. Verify that psignal and
# psiginfo print what we expect to stderr.
#

set -o errexit
set -o pipefail

ps_root=$(dirname $0)
ps_sig32=$ps_root/psignal-5097.32
ps_sig64=$ps_root/psignal-5097.64
ps_out=/tmp/$(basename $0).$$

function fatal
{
	typeset msg="$*"
	echo "Test Failed: $msg" >&2
	exit 1
}

function test_one
{
	typeset prog=$1
	typeset outfile=$ps_out.test

	$prog >/dev/null 2>$outfile || fatal "$prog unexpectedly failed"
	diff $ps_out $outfile || fatal "$ps_out and $outfile differ " \
	    "unexpectedly"
	rm -f $outfile
}

cat > $ps_out <<EOF
hello world: Segmentation Fault
Information Request
hello world : Segmentation Fault ( from process  0 )
Information Request ( from process  0 )
EOF

[[ $? -ne 0 ]] && fatal "failed to set up output file"
test_one $ps_sig32
test_one $ps_sig64
rm -f $ps_out
exit 0
