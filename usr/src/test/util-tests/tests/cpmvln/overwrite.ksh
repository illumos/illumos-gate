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
# Copyright 2024 Oxide Computer Company
#

#
# This test exercises the various overwriting, interactivity, and related
# features of cp, mv, and ln (which are all built from the same source). Each
# program may be set up to operate interactively (-i), to not touch a file if it
# already exists (-n), and to forcefully remove it anyways (-f). cp implements
# -i and -n, -f means something different. mv implements all three flags. ln
# implements -i and -f (-n is a pseudo-default).
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

ovr_exit=0
ovr_arg0=$(basename $0)
ovr_tdir=$(dirname $0)
ovr_mkobj="$ovr_tdir/mkobj"
ovr_check="$ovr_tdir/checker"
ovr_work="/tmp/$ovr_arg0.$$"

typeset -A ovr_files=(
	["a"]=(type="file" path="$ovr_work/a")
	["b"]=(type="file" path="$ovr_work/b")
	["c"]=(type="noperms" path="$ovr_work/c")
	["fifo"]=(type="fifo" path="$ovr_work/fifo")
	["door"]=(type="door" path="$ovr_work/door")
	["uds"]=(type="uds" path="$ovr_work/uds")
	["symlink"]=(type="symlink" path="$ovr_work/symlink")
	["dangle"]=(type="dangle" path="$ovr_work/dangle")
	["dir"]=(type="dir" path="$ovr_work/dir")
	["dir/a"]=(type="file-dm" path="$ovr_work/dir/a")
	["dir/b"]=(type="empty" path="$ovr_work/dir/b")
	["dir/c"]=(type="noperms-dm" path="$ovr_work/dir/c")
	["dir/fifo"]=(type="fifo-dm" path="$ovr_work/dir/fifo")
	["dir/door"]=(type="door-dm" path="$ovr_work/dir/door")
	["dir/uds"]=(type="uds-dm" path="$ovr_work/dir/uds")
	["dir/symlink"]=(type="symlink-dm" path="$ovr_work/dir/symlink")
	["dir/dangle"]=(type="dangle-dm" path="$ovr_work/dir/dangle")
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
	ovr_exit=1
}

function cleanup
{
	rm -rf $ovr_work/
}

#
# Make the files that are required for this particular test.
#
function setup_files
{
	mkdir "$ovr_work" || fatal "failed to make test directory"
	for f in $@; do
		typeset targ=${ovr_files[$f].path}
		typeset ftype=${ovr_files[$f].type}
		case $ftype in
		file)
			echo $f > $targ || fatal "failed to create $f"
			;;
		empty)
			touch $targ || fatal "failed to create $f"
			;;
		noperms)
			echo $f > $targ || fatal "failed to create $f"
			chmod 0000 $targ || fatal "failed to chmod $f"
			;;
		fifo)
			$ovr_mkobj -f $targ || fatal "failed to make fifo"
			;;
		door)
			$ovr_mkobj -d $targ || fatal "failed to make door"
			;;
		uds)
			$ovr_mkobj -s $targ || fatal "failed to make uds"
			;;
		symlink)
			ln -s ${ovr_files["b"].path} $targ || \
			    fatal "failed to make symlink"
			;;
		dangle)
			ln -s "$ovr_work/enoent" $targ || \
			     fatal "failed to make dangling symlink"
			;;
		dir)
			mkdir -p $targ || fatal "failed to make directory"
			;;
		*)
			fatal "encountered unknown type $f: $ftype"
		esac
	done
}

#
# Check files remain what we expect at this point. Arguments passed should be
# the short form.
#
function check_files
{
	typeset desc=$1
	shift
	for f in $@; do
		typeset targ=${ovr_files[$f].path}
		typeset ftype=${ovr_files[$f].type}
		typeset data=
		case $ftype in
		file*)
			#
			# A file should have the data that matches its short
			# name inside of it.
			#
			typeset exp=${f##*/}
			data=$(cat $targ)
			if [[ $data != $exp ]]; then
				warn "$desc: found unexpected file data $data" \
				    "expected $exp"
				return 1
			fi
			;;
		noperms*)
			if ! $ovr_check -n $targ; then
				warn "$desc: $targ was clobbered"
				return 1
			fi
			;;
		fifo*)
			if [[ ! -p $targ ]]; then
				warn "$desc: $targ was is somehow no longer" \
				    "a pipe: $(ls -l $targ)"
				return 1
			fi
			;;
		door*)
			if ! $ovr_check -d $targ; then
				warn "$desc: $targ was clobbered"
				return 1
			fi
			;;
		uds*)
			if [[ ! -S $targ ]]; then
				warn "$desc: $targ was is somehow no longer" \
				    "a socket: $(ls -l $targ)"
				return 1
			fi
			;;
		symlink*|dangle*)
			if [[ ! -L $targ ]]; then
				warn "$desc: $targ was is somehow no longer" \
				    "a symlink: $(ls -l $targ)"
				return 1
			fi
			;;
		dir)
			if [[ ! -d $targ ]]; then
				warn "$desc: directory $targ was removed?!"
				return 1
			fi
			;;
		*)
			fatal "encountered unknown type $f: $ftype"
		esac
	done

	return 0
}

function check_data
{
	typeset desc=$1
	typeset targ=$2
	typeset expect=$3
	typeset data=

	data=$(cat $targ)
	if [[ $data != $expect ]]; then
		warn "$desc: $targ wasn't overwritten found $data"
		return 1;
	fi

	return 0
}

#
# Run a test we expect to fail and verify that files haven't changed.
#
function exp_fail
{
	typeset desc="$1"
	typeset prog="$2"
	typeset files="$3"
	typeset -a args

	setup_files $files
	for f in $files; do
		args+=(${ovr_files[$f].path})
	done

	if $prog ${args[@]} 2>/dev/null; then
		warn "$desc: command returned 0, but expected failure"
		cleanup
		return
	fi

	check_files "$desc" "$files" && printf "TEST PASSED: %s\n" "$desc"
	cleanup
}

#
# Run a test where we want to check a particular file's contents after the test
# passes. The optional last pipe argument is used for testing interactive mode
# (whether or not a prompt appears is a different question). Interactive mode
# requires we don't have pipefail turned on to avoid propagating an error when
# the initial program gets EPIPE or a signal.
#
function exp_pass
{
	typeset desc="$1"
	typeset prog="$2"
	typeset files="$3"
	typeset expect="$4"
	typeset pipe="$5"
	typeset ret=
	typeset -a args

	setup_files $files
	for f in $files; do
		args+=(${ovr_files[$f].path})
	done

	if [[ -z "$pipe" ]]; then
		$prog ${args[@]}
		ret=$?
	else
		set +o pipefail
		$pipe | $prog ${args[@]} 2>/dev/null
		ret=$?
		set -o pipefail
	fi

	if (( ret != 0 )); then
		warn "$desc: command failed, but expected success"
		cleanup
		return
	fi

	check_data "$desc" "${args[-1]}" "$expect" && \
	    printf "TEST PASSED: %s\n" "$desc"
	cleanup
}

#
# Variant on exp_pass that expects all the input files to remain the same.
#
function exp_retain
{
	typeset desc="$1"
	typeset prog="$2"
	typeset files="$3"
	typeset -a args

	setup_files $files
	for f in $files; do
		args+=(${ovr_files[$f].path})
	done

	if ! $prog ${args[@]}; then
		warn "$desc: command failed, but expected success"
		cleanup
		return
	fi

	if check_files "$desc" "$files"; then
		printf "TEST PASSED: %s\n" "$desc"
	fi
	cleanup
}

#
# Tests for a directory. We always set up the files in the directory in addition
# to what was asked for. Then based on our expectations we make sure that the
# files were created that we expect. All tests in here should succeed.
#
function exp_dir
{
	typeset desc="$1"
	typeset prog="$2"
	typeset files="$3"
	typeset rval="$4"
	typeset exp="$5"
	typeset bdata="$6"
	typeset pipe="$7"
	typeset pass=0
	typeset -a args

	setup_files $files dir dir/b
	for f in $files; do
		args+=(${ovr_files[$f].path})
	done

	if [[ -z "$pipe" ]]; then
		$prog ${args[@]} 2>/dev/null
		ret=$?
	else
		set +o pipefail
		$pipe | $prog ${args[@]} 2>/dev/null
		ret=$?
		set -o pipefail
	fi

	if (( ret != rval )); then
		warn "$desc: command returned $ret, but expected $rval"
		cleanup
		return
	fi

	if (( ret != 0 )); then
		cleanup
		return;
	fi

	check_files "$desc" $exp || pass=1
	check_data "$desc" "${ovr_files[dir/b].path}" "$bdata" || pass=1
	(( pass == 0 )) && printf "TEST PASSED: %s\n" "$desc"
	cleanup
}

trap cleanup EXIT

#
# Start with ln which should fail without -f. Same with ln -s (a different code
# path).
#
exp_fail "ln doesn't clobber a file (ln a b)" "$LN" "a b"
exp_fail "ln doesn't clobber a file without perms (ln a c)" "$LN" "a c"
exp_fail "ln doesn't clobber a uds (ln a uds)" "$LN" "a uds"
exp_fail "ln doesn't clobber a fifo (ln a fifo)" "$LN" "a fifo"
exp_fail "ln doesn't clobber a door (ln a door)" "$LN" "a door"
exp_fail "ln doesn't clobber a valid symlink (ln a symlink)" "$LN" "a symlink"
exp_fail "ln doesn't clobber a dangling symlink (ln a dangle)" "$LN" "a dangle"

exp_fail "ln -s doesn't clobber a file (ln -s a b)" "$LN -s" "a b"
exp_fail "ln -s doesn't clobber a file without perms (ln -s a c)" "$LN -s" "a c"
exp_fail "ln -s doesn't clobber a uds (ln -s a uds)" "$LN -s" "a uds"
exp_fail "ln -s doesn't clobber a fifo (ln -s a fifo)" "$LN -s" "a fifo"
exp_fail "ln -s doesn't clobber a door (ln -s a door)" "$LN -s" "a door"
exp_fail "ln -s doesn't clobber a valid symlink (ln -s a symlink)" "$LN -s" \
    "a symlink"
exp_fail "ln -s doesn't clobber a dangling symlink (ln -s a dangle)" "$LN -s" \
    "a dangle"

#
# Now basic cp tests. We expect cp to fail on most of these because it doesn't
# have -f specified and therefore can't open the file without permissions or
# replace and deal with the socket and door. We don't use the fifo because it
# will basically just cause us to block.
#
exp_pass "cp works on a file (cp a b)" "$CP" "a b" "a"
exp_pass "XPG cp works on a file (cp a b)" "$XCP" "a b" "a"
exp_fail "cp fails on a file without perms (cp a c)" "$CP" "a c"
exp_fail "XPG cp fails on a file without perms (cp a c)" "$XCP" "a c"
exp_fail "cp fails on a uds (cp a sock)" "$CP" "a uds"
exp_fail "cp fails on a door (cp a door)" "$CP" "a door"
exp_pass "cp works on a symlink (cp a symlink)" "$CP" "a symlink" "a"
exp_pass "cp works on a dangling symlink (cp a dangle)" "$CP" "a dangle" "a"

#
# Basic mv tests. We expect mv to work on most things, but the door is a bit
# complicated because rename will fail with EBUSY, but that depends on the file
# system unfortunately (seems to fail on ZFS but work on tmpfs).
#
exp_pass "mv works on a file (mv a b)" "$MV" "a b" "a"
exp_pass "mv works on a fifo (mv a fifo)" "$MV" "a fifo" "a"
exp_pass "mv works on a uds (mv a sock)" "$MV" "a uds" "a"
exp_pass "mv works on a symlink (mv a symlink)" "$MV" "a symlink" "a"
exp_pass "mv works on a dangling symlink (mv a dangle)" "$MV" "a dangle" "a"

#
# Now we go into -f versions and cases where -f trumps -i. This should cause
# everything to work for ln. For cp, the fifo and door will not work because it
# will not remove them. We don't test the fifo due to hangs. For mv we expect
# everything expect the door (which we skip) to work.
#
exp_pass "ln -f clobbers a file (ln -f a b)" "$LN -f" "a b" "a"
exp_pass "ln -f clobbers a file without perms (ln -f a c)" "$LN -f" "a c" "a"
exp_pass "ln -f clobbers a uds (ln -f a uds)" "$LN -f" "a uds" "a"
exp_pass "ln -f clobbers a fifo (ln -f a fifo)" "$LN -f" "a fifo" "a"
exp_pass "ln -f clobbers a door (ln -f a door)" "$LN -f" "a door" "a"
exp_pass "ln -f clobbers a valid symlink (ln -f a symlink)" "$LN -f" \
    "a symlink" "a"
exp_pass "ln -f clobber a dangling symlink (ln -f a dangle)" "$LN -f" \
    "a dangle" "a"
exp_pass "ln -f beats -i on a file (ln -if a b)" "$LN -if" "a b" "a"
exp_pass "ln -f beats -i on a file (ln -ifif a b)" "$LN -ifif" "a b" "a"

exp_pass "ln -sf clobbers a file (ln -sf a b)" "$LN -sf" "a b" "a"
exp_pass "ln -sf clobbers a file without perms (ln -sf a c)" "$LN -sf" "a c" "a"
exp_pass "ln -sf clobbers a uds (ln -sf a uds)" "$LN -sf" "a uds" "a"
exp_pass "ln -sf clobbers a fifo (ln -sf a fifo)" "$LN -sf" "a fifo" "a"
exp_pass "ln -sf clobbers a door (ln -sf a door)" "$LN -sf" "a door" "a"
exp_pass "ln -sf clobbers a valid symlink (ln -sf a symlink)" "$LN -sf" \
    "a symlink" "a"
exp_pass "ln -sf clobber a dangling symlink (ln -sf a dangle)" "$LN -sf" \
    "a dangle" "a"
exp_pass "ln -sf beats -i on a file (ln -s -if a b)" "$LN -s -if" "a b" "a"
exp_pass "ln -sf beats -i on a file (ln -s -ifif a b)" "$LN -s -ifif" "a b" "a"


exp_pass "cp -f clobbers a file (cp -f a b)" "$CP -f" "a b" "a"
exp_pass "cp -f clobbers a file without perms (cp -f a c)" "$CP -f" "a c" "a"
exp_pass "cp -f clobbers a uds (cp -f a uds)" "$CP -f" "a uds" "a"
exp_fail "cp -f leaves a door alone (cp -f a door)" "$CP -f" "a door" "a"
exp_pass "cp -f clobbers a valid symlink (cp -f a symlink)" "$CP -f" \
    "a symlink" "a"
exp_pass "cp -f clobber a dangling symlink (cp -f a dangle)" "$CP -f" \
    "a dangle" "a"

exp_pass "mv -f clobbers a file (mv -f a b)" "$MV -f" "a b" "a"
exp_pass "mv -f clobbers a file without perms (mv -f a c)" "$MV -f" "a c" "a"
exp_pass "mv -f clobbers a uds (mv -f a uds)" "$MV -f" "a uds" "a"
exp_pass "mv -f clobbers a fifo (mv -f a fifo)" "$MV -f" "a fifo" "a"
exp_pass "mv -f clobbers a valid symlink (mv -f a symlink)" "$MV -f" \
    "a symlink" "a"
exp_pass "mv -f clobber a dangling symlink (mv -f a dangle)" "$MV -f" \
    "a dangle" "a"

#
# Now cp and mv -n tests. These should leave the target file as is, but pass.
#
exp_retain "cp -n doesn't clobber a file (cp -n a b)" "$CP -n" "a b"
exp_retain "cp -n doesn't clobber a file without perms (cp -n a c)" "$CP -n" \
    "a c"
exp_retain "cp -n doesn't clobber a uds (cp -n a uds)" "$CP -n" "a uds"
exp_retain "cp -n doesn't clobber a fifo (cp -n a fifo)" "$CP -n" "a fifo"
exp_retain "cp -n doesn't clobber a door (cp -n a door)" "$CP -n" "a door"
exp_retain "cp -n doesn't clobber a valid symlink (cp -n a symlink)" "$CP -n" \
    "a symlink"
exp_retain "cp -n doesn't clobber a dangling symlink (cp -n a dangle)" \
    "$CP -n" "a dangle"

exp_retain "mv -n doesn't clobber a file (mv -n a b)" "$MV -n" "a b"
exp_retain "mv -n doesn't clobber a file without perms (mv -n a c)" "$MV -n" \
    "a c"
exp_retain "mv -n doesn't clobber a uds (mv -n a uds)" "$MV -n" "a uds"
exp_retain "mv -n doesn't clobber a fifo (mv -n a fifo)" "$MV -n" "a fifo"
exp_retain "mv -n doesn't clobber a door (mv -n a door)" "$MV -n" "a door"
exp_retain "mv -n doesn't clobber a valid symlink (mv -n a symlink)" "$MV -n" \
    "a symlink"
exp_retain "mv -n doesn't clobber a dangling symlink (mv -n a dangle)" \
    "$MV -n" "a dangle"

#
# -n, -f, and -i interleaving. None of these should cause prompts. non-XPG mv -f
# will trump -i anywhere. XPG mv -i working normally is tested later on.
#
exp_retain "cp -n always beats -f (cp -nf a b)" "$CP -nf" "a b"
exp_retain "cp -n always beats -f (cp -fn a b)" "$CP -fn" "a b"
exp_retain "cp last -n wins (cp -in a b)" "$CP -in" "a b"
exp_retain "cp last -n wins (cp -nin a b)" "$CP -nin" "a b"

exp_retain "mv last -n wins (mv -in a b)" "$MV -in" "a b"
exp_retain "mv last -n wins (mv -fn a b)" "$MV -fn" "a b"
exp_retain "mv last -n wins (mv -ifn a b)" "$MV -ifn" "a b"
exp_retain "mv last -n wins (mv -fifn a b)" "$MV -fifn" "a b"
exp_pass "mv last -f wins (mv -nf a b)" "$MV -nf" "a b" "a"
exp_pass "mv last -f wins (mv -if a b)" "$MV -if" "a b" "a"
exp_pass "mv last -f wins (mv -fif a b)" "$MV -fif" "a b" "a"
exp_pass "mv last -f wins (mv -nif a b)" "$MV -nif" "a b" "a"
exp_pass "mv -f always beats -i (non-xpg) (mv -fi a b)" "$MV -fi" "a b" "a"
exp_retain "XPG4 mv last -n wins (mv -in a b)" "$XMV -in" "a b"
exp_retain "XPG4 mv last -n wins (mv -fn a b)" "$XMV -fn" "a b"
exp_retain "XPG4 mv last -n wins (mv -ifn a b)" "$XMV -ifn" "a b"
exp_retain "XPG4 mv last -n wins (mv -fifn a b)" "$XMV -fifn" "a b"
exp_pass "XPG4 mv last -f wins (mv -nf a b)" "$XMV -nf" "a b" "a"
exp_pass "XPG4 mv last -f wins (mv -if a b)" "$XMV -if" "a b" "a"
exp_pass "XPG4 mv last -f wins (mv -fif a b)" "$XMV -fif" "a b" "a"
exp_pass "XPG4 mv last -f wins (mv -nif a b)" "$XMV -nif" "a b" "a"


#
# Now onto interactive tests. Interactivity is a bit challenging. If stdin is
# not a tty then a prompt will not appear if we're not in the XPG variant. This
# means that it'll fall back to the program default (generally speaking to
# overwrite).
#
exp_pass "XPG4 cp -i no normal file (cp -i a b)" "$XCP -i" "a b" "b" \
    "cat /dev/zero"
exp_pass "XPG4 cp -i yes normal file (cp -i a b)" "$XCP -i" "a b" "a" "yes"
exp_pass "cp -i clobbers normal file regardless (cp -i a b)" "$CP -i" "a b" \
    "a" "cat /dev/zero"

exp_pass "XPG4 mv -i no normal file (mv -i a b)" "$XMV -i" "a b" "b" \
    "cat /dev/zero"
exp_pass "XPG4 mv -i yes normal file (mv -i a b)" "$XMV -i" "a b" "a" "yes"
exp_pass "mv -i clobbers normal file regardless (mv -i a b)" "$MV -i" "a b" \
    "a" "cat /dev/zero"

exp_pass "XPG4 ln -i no normal file (ln -i a b)" "$XLN -i" "a b" "b" \
    "cat /dev/zero"
exp_pass "XPG4 ln -i yes normal file (ln -i a b)" "$XLN -i" "a b" "a" "yes"
exp_pass "ln -i clobbers normal file regardless (ln -i a b)" "$LN -i" "a b" \
    "a" "cat /dev/zero"

exp_pass "XPG4 cp -i yes beats -n normal file (cp -ni a b)" "$XCP -ni" "a b" \
    "a" "yes"
exp_pass "cp -i beats -n (cp -ni a b)" "$CP -ni" "a b" "a" "cat /dev/zero"

exp_pass "XPG4 mv -i beats -n (mv -ni a b)" "$XMV -ni" "a b" "a" "yes"
exp_pass "mv -i beats -n (mv -ni a b)" "$MV -ni" "a b" "a" "cat /dev/zero"
exp_pass "XPG4 mv -i beats -f (mv -fi a b)" "$XMV -fi" "a b" "a" "yes"

exp_pass "XPG4 ln -fi no normal file (ln -fi a b)" "$XLN -fi" "a b" "b" \
    "cat /dev/zero"
exp_pass "XPG4 ln -fi yes normal file (ln -fi a b)" "$XLN -fi" "a b" "a" "yes"
exp_pass "ln -fi clobbers normal file regardless (ln -fi a b)" "$LN -fi" \
    "a b" "a" "cat /dev/zero"

exp_pass "XPG4 ln -sfi no normal file (ln -sfi a b)" "$XLN -sfi" "a b" "b" \
    "cat /dev/zero"
exp_pass "XPG4 ln -sfi yes normal file (ln -sfi a b)" "$XLN -sfi" "a b" "a" \
    "yes"
exp_pass "ln -sfi clobbers normal file regardless (ln -sfi a b)" "$LN -sfi" \
    "a b" "a" "cat /dev/zero"

#
# Now our last bit here is to do tests that operate on multiple files into a
# directory and make sure that they end up as expected.
#
exp_dir "cp multi-file" "$CP" "a b dir" 0 "dir/a" "b"
exp_fail "cp multi-file with socket fails" "$CP" "a b uds dir"
exp_fail "cp multi-file with noperms fails" "$CP" "a b c dir"
exp_dir "cp multi-file -n" "$CP -n" "a b dir" 0 "dir/a" ""
exp_dir "XPG4 cp multi-file -i yes" "$XCP -i" "a b dir" 0 "dir/a" "b" "yes"
exp_dir "XPG4 cp multi-file -i no" "$XCP -i" "a b dir" 0 "dir/a" "" \
    "cat /dev/zero"
exp_dir "cp multi-file -i clobbers anyways" "$CP -i" "a b dir" 0 "dir/a" "b" \
    "cat /dev/zero"

exp_dir "ln multi-file" "$LN" "a b dir" 2
exp_fail "ln multi-file with door fails" "$LN" "a door dir"
exp_dir "ln multi-file with socket works" "$LN" "a uds dir" 0 "dir/a dir/uds" ""
exp_dir "ln multi-file with noperms works" "$LN" "a c dir" 0 "dir/a dir/c" ""
exp_dir "ln multi-file -f" "$LN -f" "a b dir" 0 "dir/a" "b"
exp_dir "XPG4 ln multi-file -i yes" "$XLN -i" "a b dir" 0 "dir/a" "b" "yes"
exp_dir "XPG4 ln multi-file -i no" "$XLN -i" "a b dir" 0 "dir/a" "" \
    "cat /dev/zero"
exp_dir "ln multi-file -i clobbers anyways" "$LN -i" "a b dir" 0 "dir/a" "b" \
    "cat /dev/zero"

exp_dir "ln -s multi-file" "$LN -s" "a b dir" 2
exp_dir "ln -s multi-file with door works" "$LN -s" "a door dir" 0
exp_dir "ln -s multi-file with socket works" "$LN -s" "a uds dir" 0 \
    "dir/a dir/uds" ""
exp_dir "ln -s multi-file with noperms works" "$LN -s" "a c dir" 0 \
    "dir/a dir/c" ""
exp_dir "ln -s multi-file -f" "$LN -s -f" "a b dir" 0 "dir/a" "b"
exp_dir "XPG4 ln -s multi-file -i yes" "$XLN -s -i" "a b dir" 0 "dir/a" "b" \
    "yes"
exp_dir "XPG4 ln -s multi-file -i no" "$XLN -s -i" "a b dir" 0 "dir/a" "" \
    "cat /dev/zero"
exp_dir "ln -s multi-file -i clobbers anyways" "$LN -s -i" "a b dir" 0 "dir/a" \
    "b" "cat /dev/zero"

exp_dir "mv multi-file" "$MV" "a b c fifo door uds symlink dangle dir" 0 \
    "dir/a dir/c dir/fifo dir/door dir/uds dir/symlink dir/dangle" "b"
exp_dir "mv -n multi-file" "$MV -n" "a b c fifo door uds symlink dangle dir" 0 \
    "dir/a dir/c dir/fifo dir/door dir/uds dir/symlink dir/dangle" ""
exp_dir "mv -f multi-file" "$MV -f" "a b c fifo door uds symlink dangle dir" 0 \
    "dir/a dir/c dir/fifo dir/door dir/uds dir/symlink dir/dangle" "b"
exp_dir "mv -i multi-file clobbers" "$MV -i" \
    "a b c fifo door uds symlink dangle dir" 0 \
    "dir/a dir/c dir/fifo dir/door dir/uds dir/symlink dir/dangle" "b" \
    "cat /dev/null"
exp_dir "XPG4 mv -i multi-file no" "$XMV -i" \
    "a b c fifo door uds symlink dangle dir" 0 \
    "dir/a dir/c dir/fifo dir/door dir/uds dir/symlink dir/dangle" "" \
    "cat /dev/null"
exp_dir "XPG4 mv -i multi-file yes" "$XMV -i" \
    "a b c fifo door uds symlink dangle dir" 0 \
    "dir/a dir/c dir/fifo dir/door dir/uds dir/symlink dir/dangle" "b" "yes"

if (( ovr_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $ovr_exit
