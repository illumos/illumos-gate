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
# Copyright 2022 Oxide Computer Company
#

#
# This contains a number of basic tests for ar(1). When adding something
# to ar or fixing a bug, please expand this!
#

unalias -a
set -o pipefail

ar_arg0="$(basename $0)"
ar_data="$(dirname $0)"
ar_data0="$ar_data/ar_test0.o"
ar_data1="$ar_data/ar_test1.o"
ar_prog=/usr/bin/ar
ar_tmpdir=/tmp/ar.$$

ar_f01="$ar_tmpdir/test01.a"
ar_f10="$ar_tmpdir/test10.a"

ar_t01="ar_test0.o
ar_test1.o"
ar_t10="ar_test1.o
ar_test0.o"

strip_prog=/usr/bin/strip
dump_prog=/usr/bin/dump
nm_prog=/usr/bin/nm

ar_exit=0

function warn
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	print -u2 "TEST FAILED: $ar_arg0: $msg"
	ar_exit=1
}

function compare_files
{
	typeset base="$1"
	typeset comp="$2"
	typeset err=0

	if ! $dump_prog -g $comp | sed 1d > $comp.dump; then
		warn "failed to dump -g $comp"
		err=1
	fi

	if ! $nm_prog -P -tx $comp > $comp.nm; then
		warn "failed to nm $comp"
		err=1
	fi

	if ! diff $base.dump $comp.dump; then
		warn "$base.dump and $comp.dump don't match"
		err=1
	fi

	if ! diff $base.nm $comp.nm; then
		warn "$base.dump and $comp.dump don't match"
		err=1
	fi

	return $err
}

#
# To set things up, we first go and create two basic archives that we
# will then use as the basis for comaring various operations later.
#
function setup_baseline
{
	if ! $ar_prog cr $ar_f01 $ar_data0 $ar_data1; then
		warn "failed to create basic archive $ar_f01"
	fi

	if ! $ar_prog cr $ar_f10 $ar_data1 $ar_data0; then
		warn "failed to create basic archive $ar_f10"
	fi

	if ! $dump_prog -g $ar_f01 | sed 1d > $ar_f01.dump; then
		warn "failed to dump archive $ar_f01"
	fi

	if ! $dump_prog -g $ar_f10 | sed 1d > $ar_f10.dump; then
		warn "failed to dump archive $ar_f10"
	fi

	if ! $nm_prog -P -tx $ar_f01 > $ar_f01.nm; then
		warn "failed to nm archive $ar_f01"
	fi

	if ! $nm_prog -P -tx $ar_f10 > $ar_f10.nm; then
		warn "failed to nm archive $ar_f01"
	fi

	print "TEST PASSED: basic archive creation"
}

function strip_archive
{
	typeset file="$1"
	typeset output=

	if ! $strip_prog $file 2>/dev/null; then
		warn "failed to strip $alt"
		return 1
	fi

	output=$($dump_prog -g $file)
	if [[ -n "$output" ]]; then
		warn "stripped file $file somehow has an ar header"
		return 1
	fi

	return 0
}

#
# Validate that stripping and regenerating a symbol table actually
# works.
#
function test_s
{
	typeset alt="$ar_tmpdir/s.a"
	typeset output=

	if ! cp $ar_f01 $alt; then
		warn "failed to copy file"
		return
	fi

	if ! strip_archive $alt; then
		return
	fi

	if ! $ar_prog s $alt; then
		warn "restore symbol table with ar s"
	fi

	if compare_files "$ar_f01" "$alt"; then
		print "TEST PASSED: restoring stripped archive with -s"
	fi

	if ! strip_archive $alt; then
		return
	fi

	if ! $ar_prog st $alt >/dev/null; then
		warn "restore symbol table with ar st"
	fi

	if compare_files "$ar_f01" "$alt"; then
		print "TEST PASSED: restoring stripped archive with -st"
	fi

	if ! strip_archive $alt; then
		return
	fi

	output=$($ar_prog sv $alt 2>&1)
	if [[ "$output" == "ar: writing $alt" ]]; then
		print "TEST PASSED: ar -sv has proper output"
	else
		warn "ar -sv has unexpected output: $output"
	fi

	if compare_files "$ar_f01" "$alt"; then
		print "TEST PASSED: restoring stripped archive with -sv"
	fi
}

#
# Ensure that use of -s and -r still works. This is a regression test
# for the original integration of standalone -s support.
#
function test_rs
{
	typeset alt="$ar_tmpdir/rs.a"

	if ! $ar_prog rs $alt $ar_data1 $ar_data0; then
		warn "ar -rs: did not create an archive"
	fi

	if ! compare_files $ar_f10 $alt; then
		warn "ar -rs: did not create expected file"
	else
		print "TEST PASSED: ar -rs creates archives"
	fi

	rm -f $alt

	if ! $ar_prog crs $alt $ar_data1 $ar_data0; then
		warn "ar -crs: did not create an archive"
	fi

	if ! compare_files $ar_f10 $alt; then
		warn "ar -crs: did not create expected file"
	else
		print "TEST PASSED: ar -crs creates archives"
	fi
}

#
# Verify that basic ar -r invocations ultimately end up creating what
# we'd expect.
#
function test_incremental
{
	typeset alt="$ar_tmpdir/incr.a"

	if ! $ar_prog cr $alt $ar_data0; then
		warn "incremental archive: failed to create archive"
		return
	fi

	if ! $ar_prog cr $alt $ar_data1; then
		warn "incremental archive: failed to add to archive"
		return
	fi

	if ! compare_files $ar_f01 $alt; then
		warn "incremental archive: did not create expected file"
	else
		print "TEST PASSED: incremental archive creation"
	fi

}

#
# Validate that ar's various -a and -b variants work.
#
function test_pos
{
	typeset alt="$ar_tmpdir/pos.a"

	if ! $ar_prog cr $alt $ar_data1; then
		warn "positional tests: failed to create archive"
		return;
	fi

	if ! $ar_prog -cra ar_test1.o $alt $ar_data0; then
		warn "positional tests: -a append failed"
		return
	fi

	if ! compare_files $ar_f10 $alt; then
		warn "positional tests: -cra archive is incorrect"
	else
		print "TEST PASSED: positional tests: ar -cra"
	fi

	rm -f $alt

	if ! $ar_prog cr $alt $ar_data1; then
		warn "positional tests: failed to create archive"
		return;
	fi

	if ! $ar_prog -crb ar_test1.o $alt $ar_data0; then
		warn "positional tests: -b prepend failed"
		return
	fi

	if ! compare_files $ar_f01 $alt; then
		warn "positional tests: -crb archive is incorrect"
	else
		print "TEST PASSED: positional tests: ar -crb"
	fi

	rm -f $alt

	if ! $ar_prog cr $alt $ar_data1; then
		warn "positional tests: failed to create archive"
		return;
	fi

	if ! $ar_prog -cri ar_test1.o $alt $ar_data0; then
		warn "positional tests: -i prepend failed"
		return
	fi

	if ! compare_files $ar_f01 $alt; then
		warn "positional tests: -cri archive is incorrect"
	else
		print "TEST PASSED: positional tests: ar -cri"
	fi

}

#
# Go through and validate the various versions of ar x.
#
function test_x
{
	typeset out0="$ar_tmpdir/ar_test0.o"
	typeset out1="$ar_tmpdir/ar_test1.o"
	typeset output=

	rm -f $out0 $out1

	if ! $ar_prog x $ar_f01; then
		warn "ar -x: failed to extract files"
	fi

	if cmp -s $out0 $ar_data0 && cmp -s $out1 $ar_data1; then
		print "TEST PASSED: ar -x"
	else
		warn "ar -x: extracted files differs"
	fi

	rm -f $out0 $out1
	echo elberth > $out0

	#
	# For some reason, ar -Cx will actually fail if you have an
	# existing file. It seems a bit weird as it means you can't
	# extract existing files (depdendent on order), but that's how
	# it goes.
	#
	if $ar_prog Cx $ar_f01 ar_test0.o; then
		warn "ar -Cx: failed to extract file that wasn't in fs\n"
	fi

	output=$(cat $out0)
	if [[ "$output" != "elberth" ]]; then
		warn "ar -Cx: overwrote pre-existing file"
	else
		print "TEST PASSED: ar -Cx did not overwrite existing file"
	fi

	if ! $ar_prog Cx $ar_f01 ar_test1.o; then
		warn "ar -Cx: failed to extract file that wasn't in fs\n"
	fi

	if cmp -s $out1 $ar_data1; then
		print "TEST PASSED: ar -Cx extracted file that didn't exist"
	else
		warn "ar -Cx: failed to extract file that exists"
	fi
}

#
# Variant of -x that ensures we restore stripped archives.
#
function test_xs
{
	typeset alt="$ar_tmpdir/xs.a"
	typeset out0="$ar_tmpdir/ar_test0.o"
	typeset out1="$ar_tmpdir/ar_test1.o"

	rm -f $out0 $out1

	if ! cp $ar_f01 $alt; then
		warn "failed to copy file"
		return
	fi

	if ! strip_archive $alt; then
		return
	fi

	if ! $ar_prog xs $alt; then
		warn "ar -xs: failed to extract files"
	fi

	if cmp -s $out0 $ar_data0 && cmp -s $out1 $ar_data1 && \
	    compare_files "$ar_f01" "$alt"; then
		print "TEST PASSED: ar -xs"
	else
		warn "ar -xs: extracted and restore archive differ"
	fi
}

function test_m
{
	typeset alt="$ar_tmpdir/pos.a"

	if ! cp $ar_f01 $alt; then
		warn "failed to copy file"
		return
	fi

	if ! $ar_prog ma ar_test1.o $alt ar_test0.o; then
		warn "ar -ma: failed didn't work"
	fi

	if compare_files "$ar_f10" "$alt"; then
		print "TEST PASSED: ar -ma"
	else
		warn "ar -ma: did not create expected archive"
	fi

	if ! $ar_prog mb ar_test1.o $alt ar_test0.o; then
		warn "ar -ma: failed didn't work"
	fi

	if compare_files "$ar_f01" "$alt"; then
		print "TEST PASSED: ar -mb"
	else
		warn "ar -mb: did not create expected archive"
	fi
}

function test_t
{
	typeset output=

	output=$($ar_prog t $ar_f01)
	if [[ "$ar_t01" != "$output" ]]; then
		warn "ar t: mismatched output on $ar_t01, found $output"
	else
		print "TEST PASSED: ar -t (output 01)"
	fi

	output=$($ar_prog t $ar_f10)
	if [[ "$ar_t10" != "$output" ]]; then
		warn "ar t: mismatched output on $ar_f10, found $output"
	else
		print "TEST PASSED: ar -t (output 10)"
	fi
}

function test_q
{
	typeset alt="$ar_tmpdir/q.a"

	if ! $ar_prog q $alt $ar_data1 $ar_data0; then
		warn "ar -q: did not create an archive"
	fi

	if ! compare_files $ar_f10 $alt; then
		warn "ar -q: did not create expected file"
	else
		print "TEST PASSED: ar -q creates archives"
	fi

	rm -f $alt

	if ! $ar_prog cq $alt $ar_data1 $ar_data0; then
		warn "ar -rs: did not create an archive"
	fi

	if ! compare_files $ar_f10 $alt; then
		warn "ar -cq: did not create expected file"
	else
		print "TEST PASSED: ar -cq creates archives"
	fi

	rm -f $alt

	if ! $ar_prog cqs $alt $ar_data1 $ar_data0; then
		warn "ar -cqs: did not create an archive"
	fi

	if ! compare_files $ar_f10 $alt; then
		warn "ar -cqs: did not create expected file"
	else
		print "TEST PASSED: ar -cqs creates archives"
	fi

}

function test_err
{
	if $ar_prog $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args "$@", but passed"
	else
		printf "TEST PASSED: invalid arguments %s\n" "$*"
	fi
}

#
# Before we begin execution, set up the environment such that we have a
# standard locale and that umem will help us catch mistakes.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default

if ! mkdir "$ar_tmpdir"; then
	printf "failed to make output directory %s\n" "$ar_tmpdir" >&2
	exit 1
fi

if ! cd "$ar_tmpdir"; then
	printf "failed to cd into output directory %s\n" "$ar_tmpdir" >&2
	exit 1
fi

if [[ ! -d "$ar_data" ]]; then
	printf "failed to find data directory %s\n" "$ar_data" >&2
	exit 1
fi

if [[ -n $AR ]]; then
	echo overwrote AR as $AR
	ar_prog=$AR
fi

setup_baseline
test_s
test_rs
test_incremental
test_pos
test_x
test_xs
test_m
test_t
test_q

#
# Note, there are many cases here which probably should be failures and
# aren't (e.g. ar -mabi) because that's how the tool works today. With
# proper regression testing of building 3rd party packages this could be
# changed.
#
test_err ""
test_err "-z"
test_err "-d"
test_err "-d" "$ar_tmpdir/enoent"
test_err "-d" "$ar_f01" "foobar.exe"
test_err "-m" "$ar_tmpdir/enoent"
test_err "-ma" "foobar.exe" "$ar_tmpdir/enoent"
test_err "-mb" "foobar.exe" "$ar_tmpdir/enoent"
test_err "-mi" "foobar.exe" "$ar_tmpdir/enoent"
test_err "-p" "$ar_tmpdir/enoent"
test_err "-P" "$ar_tmpdir/enoent"
test_err "-q"
test_err "-qa" "foobar.exe" "$ar_f0.a"
test_err "-qb" "foobar.exe" "$ar_f0.a"
test_err "-qi" "foobar.exe" "$ar_f0.a"
test_err "-qa" "ar_test0.o" "$ar_f0.a"
test_err "-qb" "ar_test0.o" "$ar_f0.a"
test_err "-qi" "ar_test0.o" "$ar_f0.a"
test_err "-r"
test_err "-ra" "foobar.exe"
test_err "-ra" "foobar.exe" "$ar_tmpdir/enoent"
test_err "-rb" "foobar.exe"
test_err "-rb" "foobar.exe" "$ar_tmpdir/enoent"
test_err "-ri" "foobar.exe"
test_err "-ri" "foobar.exe" "$ar_tmpdir/enoent"
test_err "-t"
test_err "-t" "$ar_tmpdir/enoent"
test_err "-x"
test_err "-x" "$ar_tmpdir/enoent"
test_err "-s"
test_err "-s" "$ar_tmpdir/enoent"
test_err "-s" "$ar_f01" "$ar_f10"
test_err "-sz" "$ar_f01"
test_err "-rd"
test_err "-xd"
test_err "-qp"

if (( ar_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

cd - >/dev/null
rm -rf "$ar_tmpdir"
exit $ar_exit
