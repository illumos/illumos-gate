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
# Copyright 2026 Oxide Computer Company
#

#
# Various tests for pwd(1). In particular the main thing this looks at is the
# behavior between the logical and physical modes (-L) and (-P).
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

#
# We don't use $PWD here as the shell enjoys setting that.
#
PWDP=${PWDP:-"/usr/bin/pwd"}

pwd_exit=0
pwd_arg0=$(basename $0)
pwd_dir=$(dirname $0)
pwd_work="/tmp/$pwd_arg0.$$"

function fatal
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	exit 1
}

function warn
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	pwd_exit=1
}

function cleanup
{
	cd $pwd_dir
	rm -rf $pwd_work/
}

function setup
{
	mkdir -p "$pwd_work/1/2/3/4" || fatal "failed to make directory chain"
	ln -s "$pwd_work/1/2" "$pwd_work/link" || fatal "failed to make " \
	    "symlink"
	ln -s "$pwd_work/link/3/4" "$pwd_work/link/zelda" || fatal "failed to make " \
	    "second symlink"
}

function run_one
{
	typeset desc="$1"
	typeset path="$2"
	typeset expect="$3"
	typeset flags="$4"
	typeset out=

	out=$(cd "$path" && $PWDP $flags)
	if [[ "$out" != "$expect" ]]; then
		warn "$desc: found path $out, but expected $expect"
	else
		printf "TEST PASSED: %s\n" "$desc"
	fi
}

function env_one
{
	typeset desc="$1"
	typeset path="$2"
	typeset expect="$3"
	typeset evar="$4"
	typeset out=

	out=$(cd "$path" && PWD=$evar $PWDP -L)
	if [[ "$out" != "$expect" ]]; then
		warn "$desc: found path $out, but expected $expect"
	else
		printf "TEST PASSED: %s\n" "$desc"
	fi
}

trap cleanup EXIT
setup

#
# Go through $pwd_work/1/2/3/4 and see that we get the right output with no
# arg, -P, and -L. We expect these all to be the same.
#
run_one "baseline dir" "$pwd_work" "$pwd_work"
run_one "baseline dir/1" "$pwd_work/1" "$pwd_work/1"
run_one "baseline dir/1/2" "$pwd_work/1/2" "$pwd_work/1/2"
run_one "baseline dir/1/2/3" "$pwd_work/1/2/3" "$pwd_work/1/2/3"
run_one "baseline dir/1/2/3/4" "$pwd_work/1/2/3/4" "$pwd_work/1/2/3/4"

run_one "baseline dir -P" "$pwd_work" "$pwd_work" "-P"
run_one "baseline dir/1 -P" "$pwd_work/1" "$pwd_work/1" "-P"
run_one "baseline dir/1/2 -P" "$pwd_work/1/2" "$pwd_work/1/2" "-P"
run_one "baseline dir/1/2/3 -P" "$pwd_work/1/2/3" "$pwd_work/1/2/3" "-P"
run_one "baseline dir/1/2/3/4 -P" "$pwd_work/1/2/3/4" "$pwd_work/1/2/3/4" "-P"

run_one "baseline dir -L" "$pwd_work" "$pwd_work" "-L"
run_one "baseline dir/1 -L" "$pwd_work/1" "$pwd_work/1" "-L"
run_one "baseline dir/1/2 -L" "$pwd_work/1/2" "$pwd_work/1/2" "-L"
run_one "baseline dir/1/2/3 -L" "$pwd_work/1/2/3" "$pwd_work/1/2/3" "-L"
run_one "baseline dir/1/2/3/4 -L" "$pwd_work/1/2/3/4" "$pwd_work/1/2/3/4" "-L"

#
# Go through link and zelda make sure that pwd and pwd -P agree, but pwd -L
# differs.
#
run_one "dir/link (no flag)" "$pwd_work/link" "$pwd_work/1/2"
run_one "dir/link (-P)" "$pwd_work/link" "$pwd_work/1/2" "-P"
run_one "dir/link (-L)" "$pwd_work/link" "$pwd_work/link" "-L"
run_one "dir/link/3 (no flag)" "$pwd_work/link/3" "$pwd_work/1/2/3"
run_one "dir/link/3 (-P)" "$pwd_work/link/3" "$pwd_work/1/2/3" "-P"
run_one "dir/link/3 (-L)" "$pwd_work/link/3" "$pwd_work/link/3" "-L"
run_one "dir/link/zelda (no flag)" "$pwd_work/link/zelda" "$pwd_work/1/2/3/4"
run_one "dir/link/zelda (-P)" "$pwd_work/link/zelda" "$pwd_work/1/2/3/4" "-P"
run_one "dir/link/zelda (-L)" "$pwd_work/link/zelda" "$pwd_work/link/zelda" "-L"
run_one "dir/1/2/zelda (no flag)" "$pwd_work/1/2/zelda" "$pwd_work/1/2/3/4"
run_one "dir/1/2/zelda (-P)" "$pwd_work/1/2/zelda" "$pwd_work/1/2/3/4" "-P"
run_one "dir/1/2/zelda (-L)" "$pwd_work/1/2/zelda" "$pwd_work/1/2/zelda" "-L"

#
# Go through the various cases that pwd -L is supposed to refuse to use its path
# and make sure that we ignore it.
#
env_one "no leading /" "$pwd_work/link" "$pwd_work/1/2" foobar
env_one ". or .. (1)" "$pwd_work/link" "$pwd_work/1/2" "$pwd_work/link/3/.."
env_one ". or .. (2)" "$pwd_work/link" "$pwd_work/1/2" "$pwd_work/link/."
env_one ". or .. (3)" "$pwd_work/link" "$pwd_work/1/2" "$pwd_work/./link/"
env_one ". or .. (4)" "$pwd_work/link" "$pwd_work/1/2" "/../$pwd_work/link/"
env_one ". or .. (5)" "$pwd_work/link" "$pwd_work/1/2" "/./$pwd_work/link/"
env_one "no match (1)" "$pwd_work/link" "$pwd_work/1/2" "/dev"
env_one "no match (2)" "$pwd_work/link" "$pwd_work/1/2" "$pwd_work/link/zelda"
env_one "no match (3)" "$pwd_work/link" "$pwd_work/1/2" "$pwd_work/link/enoent"

if (( pwd_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $pwd_exit
