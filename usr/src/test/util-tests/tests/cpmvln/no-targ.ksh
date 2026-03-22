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
# Test the various flavors of cp, mv, and ln with the -T flag. The -T flag
# briefly requires that there are always two operands and says to treat the
# destination like a file with respect to removing and everything else.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

#
# Program paths for interposing while testing.
#
MV=${MV:-"/usr/bin/mv"}
XMV=${XMV:-"/usr/xpg4/bin/mv"}
CP=${CP:-"/usr/bin/cp"}
XCP=${XCP:-"/usr/xpg4/bin/cp"}
LN=${LN:-"/usr/bin/ln"}
XLN=${XLN:-"/usr/xpg4/bin/ln"}


nt_exit=0
nt_arg0=$(basename $0)
nt_work="/tmp/$nt_arg0.$$"

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
	nt_exit=1
}

function cleanup
{
	rm -rf $nt_work/
}

function setup
{
	typeset f
	mkdir "$nt_work" || fatal "failed to make test directory"
	for f in file1 file2 file3; do
		echo $f > "$nt_work/$f" || fatal "failed to create $f"
	done

	mkdir -p "$nt_work/dir1/foo/bar" || fatal "failed to create $f"
	echo nested > "$nt_work/dir1/foo/bar/nested" || fatal \
	    "failed to create nested file"
	mkdir -p "$nt_work/empty" || fatal "failed to create $f"
}

function exp_fail
{
	typeset desc="$1"
	shift

	if $* 2>/dev/null; then
		warn "$desc unexpectedly worked"
		return
	fi

	printf "TEST PASSED: %s correctly failed\n" "$desc"
}

function check_one
{
	typeset desc="$1"
	typeset check="$2"
	typeset data="$3"
	typeset comp=$(<$check)

	if [[ "$comp" != "$data" ]]; then
		warn "$desc: $check didn't have expected data: " \
		    "found: '$comp', expected: '$data'"
		return
	fi

	printf "TEST PASSED: %s: found expected data\n" "$desc"
}

#
# Run a command that relates to a file. Check that the target file has the
# expected contents in the end.
#
function exp_pass
{
	typeset desc="$1"
	typeset check="$2"
	typeset data="$3"
	typeset comp=

	shift; shift; shift
	if ! $*; then
		warn "$desc: failed to run $*"
		return
	fi

	check_one "$desc" "$check" "$data"
}

trap cleanup EXIT

#
# First go through and verify cases where we have only one argument or where we
# have more than one argument. Normally only ln works with only a single file.
#
setup
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	exp_fail "$f -T one arg" $f -T "$nt_work/file1"
	exp_fail "$f -T three args" $f -T "$nt_work/file1" "$nt_work/file2" \
	    "$nt_work/dir1"
done

#
# First go through and make sure that things do what we expect with basic file
# to file movement without -T. We clean before every test to make sure that we
# have a pristine environment. We also do an override pass here using -f to make
# sure that we can clobber as expected.
#
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	cleanup; setup
	exp_pass "$f file to file" "$nt_work/targ" "file1" $f "$nt_work/file1" \
	    "$nt_work/targ"
	exp_pass "$f -f file to file" "$nt_work/file3" "file2" $f -f \
	    "$nt_work/file2" "$nt_work/file3"
done

#
# Now do the same, but moving contents into directories. Both with and without
# -n. -n shouldn't care because the target doesn't exist.
#
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	cleanup; setup
	exp_pass "$f file to dir" "$nt_work/dir1/file1" "file1" $f \
	    "$nt_work/file1" "$nt_work/dir1"
	cleanup; setup
	exp_pass "$f -n file to dir" "$nt_work/dir1/file1" "file1" $f -n \
	    "$nt_work/file1" "$nt_work/dir1"
done

#
# Now use -T for file to file, which basically should be the same as before for
# both overwrite or not.
#
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	cleanup; setup
	exp_pass "$f -T file to file" "$nt_work/targ" "file1" $f -T \
	    "$nt_work/file1" "$nt_work/targ"
	exp_pass "$f -Tf file to file" "$nt_work/file3" "file2" $f -Tf \
	    "$nt_work/file2" "$nt_work/file3"
done

#
# Verify that -n on its own is honored correctly for file to file. Then do the
# same with -T. The tools are inconsistent about exiting zero or not, so we
# check file contents instead.
#
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	cleanup; setup
	$f -n "$nt_work/file1" "$nt_work/file2" >/dev/null 2>/dev/null
	check_one "$f file to file -n source intact" "$nt_work/file1" "file1"
	check_one "$f file to file -n dest intact" "$nt_work/file2" "file2"
	$f -Tn "$nt_work/file1" "$nt_work/file2" >/dev/null 2>/dev/null
	check_one "$f -Tn file to file source intact" "$nt_work/file1" "file1"
	check_one "$f -Tn file to file dest intact" "$nt_work/file2" "file2"
done

#
# Now one of the major differences with -T. If we use -Tn with the target of a
# directory, nothing should happen, there shouldn't be a file inside of the
# directory, and our original file should still exist.
#
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	cleanup; setup
	$f -Tn "$nt_work/file1" "$nt_work/dir1" >/dev/null 2>/dev/null
	check_one "$f -Tn file to dir source intact" "$nt_work/file1" "file1"
	if [[ ! -d "$nt_work/dir1" ]]; then
		warn "$f -Tn file to dir incorrectly removed dir"
	else
		printf "TEST PASSED: %s -Tn file to dir dir intact\n" "$f"
	fi

	if [[ -e "$nt_work/dir1/file1" ]]; then
		warn "$f -Tn file to dir incorrectly created file"
	else
		printf "TEST PASSED: %s -Tn didn't put file in dir\n" "$f"
	fi
done

#
# Verify that if our target is an empty directory, we don't overwrite it when
# using -T. This should be true regardless of -f.
#
for f in "$LN" "$XLN" "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	cleanup; setup
	$f -Tf "$nt_work/file1" "$nt_work/empty" 2>/dev/null
	check_one "$f -Tf file to dir source intact" "$nt_work/file1" "file1"
	if [[ ! -d "$nt_work/empty" ]]; then
		warn "$f -Tf file to dir incorrectly removed dir"
	else
		printf "TEST PASSED: %s -Tf file to dir dir intact\n" "$f"
	fi

	if [[ -e "$nt_work/empty/file1" ]]; then
		warn "$f -Tn file to dir incorrectly created file"
	else
		printf "TEST PASSED: %s -Tf didn't put file in dir\n" "$f"
	fi
done

#
# Now that we have done various versions of going file->* we need to turn around
# and do dir->*. We start with the base case of a directory to a file. The
# behavior here is tool specific:
#
#  - mv does not allow this.
#  - cp does not allow this.
#  - We don't want to generate directory hardlinks with ln
#  - ln without -f will refuse because it exists. However, ln with -f will
#    normally touch it. We focus on the non -f case so we have a consistent
#    failure.
#
cleanup; setup
for f in "$LN -s" "$XLN -s" "$MV" "$XMV" "$CP" "$XCP"; do
	exp_fail "$f dir to file" $f "$nt_work/empty" "$nt_work/file1"
done

#
# Now directory to directory. In the case of non-T operation, everything should
# happily work and create it inside of the target directory. However, with -T
# the behavior is different:
#
#  - mv works if it's an empty target directory, fails otherwise. This is
#    different from when not using -T.
#  - cp does not allow this.
#  - ln -s does not allow it regardless of -f or not.
#
for f in "$LN -s" "$XLN -s" "$CP" "$XCP"; do
	cleanup; setup
	exp_fail "$f -T dir to dir" $f -T "$nt_work/dir1" "$nt_work/empty"
done

for f in "$MV" "$XMV"; do
	cleanup; setup
	exp_pass "$f -T dir to dir (empty)" "$nt_work/empty/foo/bar/nested" \
	    "nested" $f -T "$nt_work/dir1" "$nt_work/empty"
	cleanup; setup
	exp_fail "$f -T dir to dir (non-empty)" $f -T "$nt_work/empty" \
	    "$nt_work/dir1"
done

#
# Finally test a case specific to symlinks: where the source is a directory but
# the target doesn't exist. Without -T the first time it's created it goes in
# the top-level dir. The second time because it's a symlink to a directory it
# goes in the directory. Consider 'ln -s amd64 64' like we use in the build
# system. The first time it creates 64->amd64 in the top level and then
# afterwards creates amd64/amd64 which points to itself, which doesn't help
# anyone. While we are using absolute paths in the test, the same behavior
# holds.
#
for f in "$LN -s" "$XLN -s"; do
	cleanup; setup
	ln -s "$nt_work/empty" "$nt_work/64" || fatal "failed to create 64"
	exp_fail "$f -T existing dir symlink" $f -T "$nt_work/empty" \
	    "$nt_work/64"
	if ! $f -Tf "$nt_work/empty" "$nt_work/64"; then
		warn "$f -Tf existing symlink failed"
	else
		printf "TEST PASSED: %s -Tf existing dir symlink failed\n" "$f"
	fi
done

if (( nt_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $nt_exit
