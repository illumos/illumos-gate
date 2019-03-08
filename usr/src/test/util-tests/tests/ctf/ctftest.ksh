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
# Copyright (c) 2019, Joyent, Inc.
#

#
# Run all of the various CTF tests
#

unalias -a
#set -o xtrace

if [[ -z "$TMPDIR" ]]; then
	TMPDIR="/tmp"
fi


ctf_arg0=$(basename $0)
ctf_root=$(cd $(dirname $0) && echo $PWD)
ctf_tests=
ctf_cc="gcc"
ctf_cxx="g++"
ctf_as="as"
ctf_convert="ctfconvert"
ctf_merge="ctfmerge"
ctf_debugflags="-gdwarf-2 "
ctf_mach32="-m32"
ctf_mach64="-m64"
ctf_temp="$TMPDIR/ctftest.$$.o"
ctf_makefile="Makefile.ctftest"
ctf_nerrs=0

usage()
{
	typeset msg="$*"
	[[ -z "$msg" ]] || echo "$msg" >&2
	cat <<USAGE >&2
Usage: $ctf_arg0 [-a as] [-c cc] [-C CC] [-g flags] [-m ctfmerge] [-t ctfconvert]

	Runs the CTF test suite

	-a assembler		Use the specified assembler, defaults to 'as'
	-c compiler		Use the specified C compiler, defaults to 'gcc'
	-C compiler		Use the specified C++ compiler, defaults to 'g++'
	-g flags		Use flags to generate debug info. Defaults to
				"-gdwarf-2".
	-m ctfmerge		Use the specified ctfmerge, defaults to
				'ctfmerge'
	-t ctfconvert		Use the specified ctfconvert, defaults to
				'ctfconvert'
USAGE
	exit 2
}


test_fail()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $msg" >&2
	((ctf_nerrs++))
}

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$ctf_arg0: $msg" >&2
	rm -f "$ctf_tmp32" "$ctf_temp64"
	exit 1
}

announce()
{
	cat << EOF
Beginning CTF tests with the following settings:
cc:		$(which $ctf_cc)
CC:		$(which $ctf_cxx)
as:		$(which $ctf_as)
ctfconvert:	$(which $ctf_convert)
ctfmerge:	$(which $ctf_merge)
32-bit CFLAGS:	$ctf_32cflags
64-bit CFLAGS:	$ctf_64cflags

EOF
}

run_one()
{
	typeset source=$1 checker=$2 flags=$3

	if ! "$ctf_cc" $flags -o "$ctf_temp" -c "$source"; then
		test_fail "failed to compile $source with flags: $flags"
		return
	fi

	if ! "$ctf_convert" "$ctf_temp"; then
		test_fail "failed to convert CTF in $source"
		return
	fi

	if ! "$checker" "$ctf_temp"; then
		test_fail "check for $source, $checker, failed"
		return
	fi

	echo "TEST PASSED: $source $flags"
}

#
# Perform a more complex build. The Makefile present will drive the
# building of the artifacts and the running of the tests based on the
# variables that we pass to it.
#
run_dir()
{
	typeset dir outdir check32 check64 flags32 flags64

	dir=$1
	outdir="$TMPDIR/ctftest.$$-$(basename $d)"
	check32=$2
	flags32=$3
	check64=$4
	flags64=$5

	if ! mkdir $outdir; then
		fatal "failed to make temporary directory '$outdir'"
	fi

	if ! make -C $dir -f Makefile.ctftest \
	    BUILDDIR="$outdir" \
	    CC="$ctf_cc" \
	    CFLAGS32="$ctf_mach32" \
	    CFLAGS64="$ctf_mach64" \
	    DEBUGFLAGS="$ctf_debugflags" \
	    CTFCONVERT="$ctf_convert" \
	    CTFMERGE="$ctf_merge" \
	    build 1>/dev/null; then
		rm -rf $outdir
		test_fail "failed to build $dir"
		return
	fi

	if ! make -C $dir -f Makefile.ctftest \
	    BUILDDIR="$outdir" \
	    CHECK32="$check32" \
	    CHECK64="$check64" \
	    run-test 1>/dev/null; then
		rm -rf $outdir
		test_fail "failed to run tests for $dir"
		return
	fi

	rm -rf $outdir
	echo "TEST PASSED: $dir (dir)"
}

#
# Find all of the tests that exist and then try to run them all. Tests
# may either be a single file or a directory.
#
run_tests()
{
	typeset t base check
	ctf_tests=$(ls "$ctf_root"/*.c)
	for t in $ctf_tests; do
		base=$(basename "$t" .c)
		check=$(echo "$base" | sed s/test-/check-/)
		if [[ -f "$ctf_root/$check" ]]; then
			run_one $t "$ctf_root/$check" "$ctf_32cflags"
			run_one $t "$ctf_root/$check" "$ctf_64cflags"
		elif [[ -f "$ctf_root/$check-32" && \
		    -f "$ctf_root/$check-64" ]]; then
			run_one $t "$ctf_root/$check-32" "$ctf_32cflags"
			run_one $t "$ctf_root/$check-64" "$ctf_64cflags"
		else
			test_fail "missing checker for $t"
		fi
	done

	for d in $(find "$ctf_root" -maxdepth 1 -type d -name 'test-*'); do
		[[ ! -f "$d/$ctf_makefile" ]] && continue
		base=$(basename "$d")
		check=$(echo "$base" | sed s/test-/check-/)
		if [[ -f "$ctf_root/$check" ]]; then
			run_dir $d "$ctf_root/$check" "$ctf_32cflags" \
			    "$ctf_root/$check" "$ctf_64cflags"
		elif [[ -f "$ctf_root/$check-32" && \
		    -f "$ctf_root/$check-64" ]]; then
			run_dir $d "$ctf_root/$check-32" "$ctf_32cflags" \
			    "$ctf_root/$check-64" "$ctf_64cflags"
		else
			test_fail "missing checker for $t"
		fi
	done

	outdir="$TMPDIR/ctftest.$$"

	for f in $(find "$ctf_root" -maxdepth 1 -type f -name 'ctftest-*'); do
		if ! mkdir $outdir; then
			fatal "failed to make temporary directory '$outdir'"
		fi

		echo "Running $f in $outdir"

		(cd $outdir && $f)

		if [[ $? -ne 0 ]]; then
			test_fail "$f failed"
		else
			echo "TEST PASSED: $f"
		fi

		rm -rf $outdir
	done
}

while getopts ":a:C:c:g:m:t:" c $@; do
	case "$c" in
	a)
		ctf_as=$OPTARG
		;;
	C)
		ctf_cxx=$OPTARG
		;;
	c)
		ctf_cc=$OPTARG
		;;
	g)
		ctf_debugflags=$OPTARG
		;;
	m)
		ctf_merge=$OPTARG
		;;
	t)
		ctf_convert=$OPTARG
		;;
	:)
		usage "option requires an argument -- $OPTARG"
		;;
	*)
		usage "invalid option -- $OPTARG"
		;;
	esac
done

ctf_32cflags="$ctf_mach32 $ctf_debugflags"
ctf_64cflags="$ctf_mach64 $ctf_debugflags"

export ctf_as ctf_cc ctf_cxx ctf_debugflags ctf_merge ctf_convert

announce

run_tests

if [[ $ctf_nerrs -ne 0 ]]; then
	if [[ $ctf_nerrs -eq 1 ]]; then
		printf "\n%s: %u test failed\n" "$ctf_arg0" "$ctf_nerrs"
	else
		printf "\n%s: %u tests failed\n" "$ctf_arg0" "$ctf_nerrs"
	fi
	exit 1
else
	printf "\n%s: All tests passed successfully\n" "$ctf_arg0"
	exit 0
fi
