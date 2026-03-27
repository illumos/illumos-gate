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
# Various tests for rm(1).
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

RM=${RM:-"/usr/bin/rm"}
XRM=${XRM:-"/usr/xpg4/bin/rm"}

rm_exit=0
rm_arg0=$(basename $0)
rm_work="/tmp/$rm_arg0.$$"

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
	rm_exit=1
}

function cleanup
{
	rm -rf $rm_work/
}

function setup
{
	mkdir "$rm_work" || fatal "failed to create directory $rm_work"
	touch "$rm_work/file0" "$rm_work/file1" "$rm_work/file2" || \
	    fatal "failed to make files"
	mkdir "$rm_work/dir" || fatal "failed to create $rm_work/dir"
	mkdir -p "$rm_work/a/b/c" || fatal "failed to create recursive dirs"
	touch "$rm_work/a/1" "$rm_work/a/b/2" "$rm_work/a/b/c/3" || \
	    fatal "failed to create files"
	touch "$rm_work/noperm" || fatal "failed to make file"
	chmod 0000 "$rm_work/noperm" || fatal "failed to chmod $rm_work/noperm"
	mkdir "$rm_work/nodir"  || fatal "failed to make $rm_work/nodir"
	chmod 0000 "$rm_work/nodir" || fatal "failed to chmod $rm_work/nodir"
}

#
# Attempt an rm command that should fail.
#
function test_fail
{
	typeset desc="$1"
	typeset exp="$2"
	typeset out=
	shift; shift

	out=$($* 2>&1 1>/dev/null)
	if (( $? == 0 )); then
		warn "$desc: $* worked, but expected it to fail with $exp"
		return
	fi

	if ! [[ "$out" =~ "$exp" ]]; then
		warn "$desc: failed with $out, but wanted $exp"
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"
}

#
# Verify all files listed have been removed from this world.
#
function check_gone
{
	typeset desc="$1"
	typeset fail=0
	typeset f
	shift

	for f in "$@"; do
		if [[ -e $f ]]; then
			warn "$desc: expected $f to be removed, but it still" \
			    "exists"
			fail=1
		fi
	done

	return $fail
}

#
# Variant of the above, but existence
#
function check_exists
{
	typeset desc="$1"
	typeset fail=0
	typeset f
	shift

	for f in "$@"; do
		if ! [[ -e $f ]]; then
			warn "$desc: expected $f to be present, but it was" \
			    "removed"
			fail=1
		fi
	done

	return $fail
}

#
# Run a basic rm command. It should pass. All arguments listed on the command line
# should not exist, though some of them may never have. It should not require
# input, but we redirect stdin to /dev/null regardless.
#
function test_rm
{
	typeset desc="$1"
	typeset f
	shift

	if ! $* >/dev/null </dev/null; then
		warn "$desc: rm failed, but expected success"
		return
	fi

	#
	# Remove any options.
	#
	shift
	if [[ "$1" =~ -[A-Za-z]+ ]]; then
		shift
	fi

	if ! check_gone "$desc" "$@"; then
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"
}

#
# A variant of the above, but after executing all files should remain.
#
function test_remain
{
	typeset desc="$1"
	shift

	if ! $* >/dev/null 2>/dev/null </dev/null; then
		warn "$desc: rm failed, but expected success"
		return
	fi

	#
	# Remove any options.
	#
	shift
	if [[ "$1" =~ -[A-Za-z]+ ]]; then
		shift
	fi

	if ! check_exists "$desc" "$@"; then
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"
}

#
# Variant of the above where we say "yes".
#
function test_yes
{
	typeset desc="$1"
	typeset ret
	shift

	#
	# We need to disable pipefail briefly so the failure of the yes command
	# doesn't lead rm to accidentally fail.
	#
	set +o pipefail
	yes | $* >/dev/null 2>/dev/null
	ret=$?
	set -o pipefail
	if (( ret != 0 )); then
		warn "$desc: rm failed, but expected success"
		return
	fi

	#
	# Remove any options.
	#
	shift
	if [[ "$1" =~ -[A-Za-z]+ ]]; then
		shift
	fi

	if ! check_gone "$desc" "$@"; then
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"

}

#
# Run an rm command that should produce verbose output. We employ sort here to
# put the files in a deterministic order so that way if we ever end up with
# multiple files in a directory we aren't subject to the dirent iteration order.
#
function test_verbose
{
	typeset desc="$1"
	typeset exp="$2"
	typeset out
	shift; shift

	out=$($* | sort)
	if (( $? != 0 )); then
		warn "$desc: rm failed, but expected success"
		return
	fi

	shift
	if [[ "$1" =~ -[A-Za-z]+ ]]; then
		shift
	fi

	if ! check_gone "$desc" "$@"; then
		return
	fi

	if [[ "$out" != "$exp" ]]; then
		warn "expected verbose output $exp, found $out"
		return
	fi

	printf "TEST PASSED: %s\n" "$desc"
}

trap cleanup EXIT

#
# Ensure that we're not running as uid 0 to minimize any chance of some of the
# DAC privileges.
#
if (( $(id -u) == 0 )); then
	echo "This test should be run as a non-privileged user like nobody." >&2
	exit 1
fi

#
# First test various failure scenarios.
#
for f in "$RM" "$XRM"; do
	test_fail "$f with no arguments" "usage: rm" $f
	test_fail "$f with bad arg -@" "illegal option -- @" $f -@
	test_fail "$f on non-existent file fails" "No such file or directory" \
	    $f "$rm_work/enoent"
done

#
# Verify basic rm activity
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_rm "$f basic file" $f "$rm_work/file0"
	test_rm "$f multiple files" $f "$rm_work/file1" "$rm_work/file2"
	test_rm "$f recursive dir" $f -r "$rm_work/a"
	cleanup ; setup
	test_rm "$f files and dirs" $f -r "$rm_work/a" "$rm_work/dir" \
	    "$rm_work/file0" "$rm_work/file1" "$rm_work/file2"
done

#
# Verify rm removes other operands even if one fails. Similarly, no error on -f.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_fail "$f fails with present/missing files" \
	    "No such file or directory" $f "$rm_work/file0" "$rm_work/ENOENT" \
	    "$rm_work/file1" "$rm_work/file2"
	check_gone "$f removed other files after ENOENT" "$rm_work/file0" \
	    "$rm_work/file1" "$rm_work/file2"
	cleanup; setup
	test_rm "$f -f passes with present/missing files" $f -f \
	    "$rm_work/file0" "$rm_work/ENOENT" "$rm_work/file1" \
	    "$rm_work/file2"
done

#
# Test our behavior on directories: rm should fail on an empty directory or a
# directory with files. Next, rm -d should work on an empty directory; however,
# it should fail on a non-empty directory.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_fail "$f fails on empty directory" "is a directory" $f \
	    "$rm_work/dir"
	test_fail "$f fails on non-empty directory" "is a directory" $f \
	    "$rm_work/a"
	test_rm "$f -d removes empty directory" $f -d "$rm_work/dir"
	test_fail "$f -d doesn't remove non-empty directory" \
	    "Directory not empty" $f -d "$rm_work/a"
	test_fail "$f -df doesn't remove non-empty directory" \
	    "Directory not empty" $f -df "$rm_work/a"
done

#
# rm -i doesn't remove files when told no.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_remain "$f -i answer no 1 file" $f -i "$rm_work/file0"
	test_remain "$f -i answer no multi file" $f -i "$rm_work/file0" \
	    "$rm_work/file1" "$rm_work/file2"
	test_remain "$f -ri answer no" $f -ri "$rm_work/file0" "$rm_work/dir" \
	    "$rm_work/a"
done

#
# xpg4 rm has -i and -f as the last one wins. /usr/bin/rm has -i trump.
#
cleanup; setup
test_remain "$RM -i overrides all -f" $RM -fif "$rm_work/file0"
test_remain "$XRM last -if wins (-i)" $XRM -fifi "$rm_work/file0"
test_rm "$XRM last -if wins (-f)" $XRM -fif "$rm_work/file0"

#
# Now, test cases where we say yes to -i and verify that everything is gone.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_yes "$f -i answer yes 1 file" $f -i "$rm_work/file0"
	test_yes "$f -i answer yes two file" $f -i "$rm_work/file1" \
	    "$rm_work/file2"
	cleanup; setup
	test_yes "$f -ri answer yes, multi" $f -ri "$rm_work/file1" \
	    "$rm_work/file2" "$rm_work/dir" "$rm_work/a"
done

#
# Now onto rm's behavior when there are no write permissions. rm with no flags
# will prompt for this if we're on a tty, but not otherwise. -i will prompt. -f
# will never prompt. Do the same with an empty dir.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_remain "$f -i no perms" $f -i "$rm_work/noperm"
	test_rm "$f no perms (!tty)" $f "$rm_work/noperm"
	cleanup; setup
	test_yes "$f -i no perms (yes)" $f -i "$rm_work/noperm"
	cleanup; setup
	test_rm "$f -f no perms" $f -f "$rm_work/noperm"
	cleanup; setup
	test_remain "$f -di no perms dir" $f -di "$rm_work/nodir"
	test_rm "$f -d no perms dir (!tty)" $f -d "$rm_work/nodir"
	cleanup; setup
	test_yes "$f -di no perms dir (yes)" $f -di "$rm_work/nodir"
	cleanup; setup
	test_rm "$f -df no perms dir" $f -df "$rm_work/nodir"

done

#
# Finally, rm says it will fail and always print a message if it encounters a
# directory without write permission in rm -rf.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	chmod 0000 "$rm_work/a/b" || fatal "failed to make chmod $rm_work/a/b"
	test_fail "$f -rf non-empty non-writable dir" "Permission denied" \
	    $f -rf "$rm_work/a"
	chmod 755 "$rm_work/a/b" || fatal "failed to restore $rm_work/a/b"
done

#
# Different tests for -v.
#
for f in "$RM" "$XRM"; do
	cleanup; setup
	test_verbose "$f -v single file" "$rm_work/file0" $f -v "$rm_work/file0"
	exp=$(find $rm_work/file1 $rm_work/file2 | sort)
	test_verbose "$f -v multiple files" "$exp" $f \
	    -v "$rm_work/file2" "$rm_work/file1"
	exp=$(find "$rm_work/noperm" "$rm_work/dir" "$rm_work/a" | sort)
	test_verbose "$f -rvf multiple" "$exp" $f -rvf "$rm_work/noperm" \
	    "$rm_work/dir" "$rm_work/a"
done

if (( rm_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $rm_exit
