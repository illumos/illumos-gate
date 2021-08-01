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
# Copyright 2021 Oxide Computer Company
#

#
# The goal of this test suite is to test certain aspects of core dump
# generation and different core contents being specified. The
# 'dumper.32' and 'dumper.64' programs are designed to be told what to
# set a core content and path to, after which point we use both gcore
# and the kernel to generate a core dump for the file and verify that it
# has what we expect. The verification is done by the secmapper program.
#

unalias -a
set -o pipefail

core_arg0="$(basename $0)"
core_dir="$(dirname $0)"
core_dumper32="$core_dir/dumper.32"
core_dumper64="$core_dir/dumper.64"
core_checker="$core_dir/secmapper"

core_tmpdir="/tmp/coretest.$$"
core_exit=0

#
# This array describes the different types of core contents that we're
# going to try and generate and check against.
#
core_contents="none
ctf
debug
symtab
ctf+debug+symtab
anon+data+ctf+debug+symtab
default
default-ctf-debug-symtab
default+debug
default-symtab"

warn()
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	core_exit=1
}

core_dump_one()
{
	typeset prog="$1"
	typeset pbase=$(basename $prog)
	typeset cont="$2"
	typeset kpath="$3"
	typeset gpath="$4"
	typeset pid=

	$prog "$cont" "$kpath" &
	pid=$!
	if (( $? != 0 )); then
		warn "failed to spawn $core_dumper32: $cont $kpath"
		return 1
	fi

	#
	# This is racy, but probably should be a reasonable amount of
	# time for dumper to be ready.
	#
	for ((i = 0; i < 10; i++)) {
		if pstack $pid | grep -q 'fsigsuspend'; then
			break
		fi
	}

	if ! gcore -o "$gpath" -c "$cont" $pid >/dev/null; then
		warn "failed to gcore $pid: $prog $cont $kpath"
	fi

	kill -ABRT $pid
	fg %1

	#
	# Since we have the pid, go through and check this now.
	#
	if $core_checker $core_tmpdir/*.kernel.$c.$pid $c; then
		printf "TEST PASSED: kernel %s %s\n" "$pbase" "$c"
	else
		warn "checker failed for kernel $c"
	fi

	if $core_checker $core_tmpdir/*.gcore.$c.$pid $c; then
		printf "TEST PASSED: gcore %s %s\n" "$pbase" "$c"
	else
		warn "checker failed for gcore of $c"
	fi
}

if [[ ! -x "$core_dumper32" || ! -x "$core_dumper64" || \
     ! -f "$core_checker" ]]; then
	warn "missing expected files"
	exit $core_exit
fi

if ! mkdir "$core_tmpdir"; then
	warn "failed to create temporary directory: $core_tmpdir"
	exit $core_exit
fi

for c in $core_contents; do
	kpattern="$core_tmpdir/%f.kernel.$c.%p"
	gpattern="$core_tmpdir/%f.gcore.$c"

	core_dump_one "$core_dumper32" "$c" "$kpattern" "$gpattern"
	core_dump_one "$core_dumper64" "$c" "$kpattern" "$gpattern"

done

if (( core_exit == 0 )); then
	printf "All tests passed successfully\n"
fi

rm -rf $core_tmpdir
exit $core_exit
