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
# Copyright 2023 Oxide Computer Company
#

#
# This test goes through and runs our 32 and 64-bit bad xsave contexts
# tests using getcontextx() in lieu of the signal handler to create
# invalid states. setcontext(2) in libc will try to kill the process if
# this fails in most situations, so we basically go through and detect
# that this is the case we expect (e.g. the system call returned an
# error) and go from there.
#

unalias -a
set -o pipefail

xsave_arg0="$(basename $0)"
xsave_dir="$(dirname $0)"
xsave_bad32="$xsave_dir/xsave_baducontext.32"
xsave_bad64="$xsave_dir/xsave_baducontext.64"
xsave_exit=0

warn()
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	xsave_exit=1
}

run_single()
{
	typeset prog=$1
	typeset caseno=$2
	typeset info=
	typeset ret=
	typeset desc=
	typeset errno=

	if ! info=$($prog -i $caseno); then
		warn "failed to get test information for case $caseno"
		return
	fi

	if ! eval $info || [[ -z "$desc" ]] || [[ -z "$errno" ]]; then
		warn "failed to set test information"
	fi

	dtrace -q -w -c "$prog -r $caseno" -s /dev/stdin <<EOF
syscall::setcontext:return
/pid == \$target && arg1 != 0 && errno == $errno/
{
	printf("TEST PASSED: $desc\n");
	stop();
	raise(SIGKILL);
	exit(0);
}

syscall::setcontext:return
/pid == \$target && arg1 != 0 && errno != $errno/
{
	printf("errno mismatch: found %d, expected $errno\n", errno);
	printf("TEST FAILED: $desc\n");
	stop();
	raise(SIGKILL);
	exit(1);
}

proc:::exit
/pid == \$target/
{
	printf("TEST FAILED: $desc: exited normally\n");
	exit(1);
}
EOF
	if (( $? != 0 )); then
		xsave_exit=1
	fi
}

run_prog()
{
	typeset prog="$1"
	typeset count=

	printf "Beginning tests from %s\n" "$prog"
	count=$($prog -c)
	if (( $? != 0 || count <= 0)); then
		warn "failed to get entry count for $prog"
		return
	fi

	for ((i = 0; i < count; i++)) {
		run_single $prog $i
	}
}

run_prog $xsave_bad32
run_prog $xsave_bad64

if (( xsave_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $xsave_exit
