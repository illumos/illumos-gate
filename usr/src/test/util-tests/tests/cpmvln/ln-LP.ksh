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
# This program goes through and tests how ln acts by default and with its -L and
# -P flags as well as the default behavior. The basic summary is:
#
# 1. All of these flags should be ignored when used with -s.
# 2. -L should cause us to dereference a symlink when making a hardlink. That is
#    we should get a hardlink to the underlying object (if allowed).
# 3. -P should cause us to get a hardlink to the symlink itself.
# 4. /usr/bin/ln defaults to -P behavior. /usr/xpg4/bin/ln defaults to -L
#    behavior.
#
# Finally, we want to see how this works across a variety of symlinks to the
# following file types: regular files, directories, doors, fifos, unix domain
# sockets. We must be very careful not to create hardlinks to directories here
# as tests are sometimes run by privileged users.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

LN=${LN:-"/usr/bin/ln"}
XLN=${XLN:-"/usr/xpg4/bin/ln"}

lnlp_exit=0
lnlp_arg0=$(basename $0)
lnlp_tdir=$(dirname $0)
lnlp_mkobj="$lnlp_tdir/mkobj"
lnlp_equiv="$lnlp_tdir/equiv"
lnlp_work="/tmp/$lnlp_arg0.$$"

#
# The following table describes the files that we're testing against. hardlinks
# will not work with doors as doors are considered to be on a different file
# system. Directories will fail because we are running as a non-root user to
# ensure that we don't create hardlink to directory madness.
#
typeset -A lnlp_files=(
	["file"]=(make="touch" hard="pass" soft="pass")
	["dir"]=(make="mkdir" hard="fail" soft="pass")
	["fifo"]=(make="$lnlp_mkobj -f" hard="pass" soft="pass")
	["door"]=(make="$lnlp_mkobj -d" hard="fail" soft="pass")
	["uds"]=(make="$lnlp_mkobj -s" hard="pass" soft="pass")
)

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
	lnlp_exit=1
}

function cleanup
{
	rm -rf $lnlp_work/
}

#
# Create the series of objects and symlinks that we expect to exist.
#
function setup
{
	mkdir "$lnlp_work" || fatal "failed to make test directory"
	for f in ${!lnlp_files[@]}; do
		typeset targ="${lnlp_work}/$f"
		typeset sym="${targ}_symlink"

		${lnlp_files[$f].make} $targ || fatal "failed to make $f"
		ln -s $targ $sym || fatal "failed to create symlink to $f"
	done
}

#
# Run a single ln hardlink invocation. This invocation is expected to pass. $dst
# should match the contents of $exp.
#
function test_one_hl
{
	typeset desc="$1"
	typeset src="$lnlp_work/${2}_symlink"
	typeset exp_base="$3"
	typeset exp="$lnlp_work/$3"
	typeset dst="$lnlp_work/test"

	#
	# Remaining arguments after this are the correct ln program and flags to
	# use.
	#
	shift; shift; shift

	rm -f $dst
	if ! $* "$src" "$dst"; then
		warn "$desc: $* $src $dst failed unexpectedly"
		return
	fi

	if ! $lnlp_equiv $exp $dst; then
		warn "$desc: ln didn't result in expected file $3"
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"
}

#
# This is variant where the ln results should fail. This is generally used when
# using hardlinks on doors and directories.
#
function test_one_fail
{
	typeset desc="$1"
	typeset src="$lnlp_work/${2}_symlink"
	typeset dst="$lnlp_work/test"

	shift; shift

	rm -f $dst
	if $* "$src" "$src" 2>/dev/null; then
		warn "$desc: $* unexpectedly worked?!"
		return
	fi

	printf "TEST PASSED: %s failed correctly\n" "$desc"
}

#
# For a given version of ln and its options, run through each of the different
# valid file types and see if it passes or fails.
#
function test_series
{
	typeset bdesc="$1"
	typeset rtype="$2"

	#
	# Options after this will be the flags and type of ln invocation we
	# should use.
	#
	shift; shift
	for f in ${!lnlp_files[@]}; do
		typeset test_exp

		if [[ "$rtype" == "hard" ]]; then
			test_exp="$f"
		else
			test_exp="${f}_symlink"
		fi

		if [[ ${lnlp_files[$f].[$rtype]} == "pass" ]]; then
			test_one_hl "$bdesc: $f results in $rtype" $f \
			    $test_exp $*
		else
			test_one_fail "$bdesc: $f ${rtype}link fails" $f $*
		fi
	done
}

#
# Go through and make a symlink to each file and verify that it is a different
# inode than one that already exists. We skip doing this for every combination
# and just do it once for a file and a symlink.
#
function test_symlink
{
	typeset dst="$lnlp_work/test"
	typeset src="$lnlp_work/file"
	typeset desc="$1"
	shift

	rm -f $dst
	if ! $* $src $dst; then
		warn "$desc: $* $src $dst unexpectedly failed"
		return
	fi

	if $lnlp_equiv $src $dst 1>/dev/null 2>/dev/null; then
		warn "$desc: ln -s somehow ended up with the same inode"
		return
	fi

	src="$lnlp_work/file_symlink"
	rm -f $dst
	if ! $* $src $dst; then
		warn "$desc: $* $src $dst unexpectedly failed"
		return
	fi

	if $lnlp_equiv $src $dst 1>/dev/null 2>/dev/null; then
		warn "$desc: ln -s somehow ended up with the same inode"
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"
}

#
# Sanity check that we're not running as a privileged user. This won't catch
# some some cases where we have privileges, but this is better than nothing.
#
lnlp_uid=$(id -u)
if (( lnlp_uid == 0 )); then
	printf "Running as uid 0 is not permitted try nobody instead\n" >&2
	exit 1
fi

trap cleanup EXIT

#
# Create all of our different fields and the symlinks to them.
#
setup

#
# First test the defaults of each command.
#
test_series "$LN defaults" soft $LN
test_series "$XLN defaults" hard $XLN

#
# Now verify that they do identical thing with a single -L and -P.
#
test_series "$LN -P" soft $LN -P
test_series "$LN -L" hard $LN -L

test_series "$LN -P wins (-LP)" soft $LN -LP
test_series "$LN -P wins (-PLPLP)" soft $LN -PLPLP
test_series "$LN -P wins (-LLLP)" soft $LN -LLLP
test_series "$LN -L wins (-PL)" hard $LN -PL
test_series "$LN -L wins (-LPLPL)" hard $LN -LPLPL
test_series "$LN -L wins (-PPPL)" hard $LN -PPPL

test_series "$XLN -P wins (-LP)" soft $XLN -LP
test_series "$XLN -P wins (-PLPLP)" soft $XLN -PLPLP
test_series "$XLN -P wins (-LLLP)" soft $XLN -LLLP
test_series "$XLN -L wins (-PL)" hard $XLN -PL
test_series "$XLN -L wins (-LPLPL)" hard $XLN -LPLPL
test_series "$XLN -L wins (-PPPL)" hard $XLN -PPPL

#
# Go through and manually do a few symlink related tests.
#
test_symlink "$LN -s" $LN -s
test_symlink "$LN -s -L" $LN -s -L
test_symlink "$LN -s -P" $LN -s -P
test_symlink "$LN -s -LP" $LN -s -LP
test_symlink "$LN -s -PL" $LN -s -PL

test_symlink "$XLN -s" $XLN -s
test_symlink "$XLN -s -L" $XLN -s -L
test_symlink "$XLN -s -P" $XLN -s -P
test_symlink "$XLN -s -LP" $XLN -s -LP
test_symlink "$XLN -s -PL" $XLN -s -PL

if (( lnlp_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $lnlp_exit
