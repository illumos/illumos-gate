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
# Copyright 2018 Joyent, Inc.
#

#
# libdis test driver
#
# Tests are arranged by architecture. By default we'll run all of the
# dis tests on our current architecture only. If the -p option is passed
# to point to other correctly built gas instances, then we'll run those
# tests, verifying that the cross-dis works.
#
# Each test should begin with one of the following three keywords:
#
#	tst	- Run both the 32-bit and 64-bit versions
#	32	- Only run this with the gas 32-bit flag
#	64	- Only run this with the gas 64-bit flag
#
# For example, tst.smap.s, would be built both 32-bit and 64-bit and compared to
# its output file.
#
# Each input file should consist of a series of instructions in a function named
# 'libdis_test'. The test suite will compile this file into an object file,
# disassemble it, and compare it to the output file.
#
# For each input file, there should be a corresponding output file with the .out
# suffix instead of the .s suffix. So, if you had tst.smap.s, you should have
# tst.smap.out.
#

unalias -a
dt_arg0=$(basename $0)
dt_dis="/usr/bin/dis -qF libdis_test"
dt_diff="/usr/bin/cmp -s"
dt_defas="gas"
dt_defarch=
dt_nodefault=
dt_tests=
dt_tnum=0
dt_tfail=0
dt_tsuc=0
dt_origwd=
dt_root=
dt_faildir=0
typeset -A dt_platforms

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "$dt_arg0: $msg" >&2
	exit 1
}

usage()
{
	typeset msg="$*"
	[[ -z "$msg" ]] || echo "$msg" 2>&1
	cat <<USAGE >&2
Usage: $dt_arg0  [-n] [ -p platform=pathtoas ]... [ test ]...

	Runs all dis for the current platform or only specified tests if listed.

	-n			Don't run default platform tests
	-p platform=pathtoas	Run tests for platform using assembler. Should
				either be an absolute path or a command on the
				path.
USAGE
	exit 2
}

#
# By default, tests only run for the current platform. In other words,
# running on an x86 system only assumes that the tests in the i386
# directory should be run. If the -p option is specified, then other
# platforms will be run.
#
# Right now, we only support running this on x86 natively; however, you
# can run tests for other platforms with the -p option.
#
determine_arch()
{
	typeset arch

	arch=$(uname -p)
	[[ $? -eq 0 ]] || fatal "failed to determine host architecture"
	[[ "$arch" != "i386" ]] && fatal "dis tests are only supported on x86"
	[[ -n "$dt_nodefault" ]] && return
	dt_defarch="i386"
	dt_platforms[$dt_defarch]=$dt_defas
}

#
# Iterate over the set of platforms and verify that we both know about them and
# we can find the assembler for them.
#
check_platforms()
{
	typeset key

	for key in ${!dt_platforms[@]}; do
		typeset bin
		[[ -d $dt_root/$key ]] || fatal "encountered unknown platform: $key"

		#
		# This may be a path or something else.
		#
		bin=${dt_platforms[$key]}
		[[ -x $bin ]] && continue
		which $bin >/dev/null 2>&1 && continue
		fatal "failed to find command as absolute path or file: $bin"
	done
}

handle_failure()
{
	typeset dir reason source out
	dir=$1
	reason=$2
	source=$3
	out=$4
	faildir=

	while [[ -d failure.$dt_faildir ]]; do
		((dt_faildir++))
	done

	faildir="failure.$dt_faildir"
	mv $dir $faildir
	cp $source $faildir/
	cp $out $faildir/
	printf "%s " "failed "
	[[ -n $reason ]] && printf "%s " $reason
	printf "%s\n" "$faildir"
	((dt_tfail++))
}

#
# Check
#
test_one()
{
	typeset gflags source cmp disfile outfile extra aserr diserr
	dir="dis.$$"
	gflags=$1
	source=$2
	cmp=$3
	extra=$4

	outfile=$dir/dis.o
	aserr=$dir/as.stderr
	disfile=$dir/libdis.out
	diserr=$dir/dis.stderr

	((dt_tnum++))
	mkdir -p $dir || fatal "failed to make directory $dir"

	printf "testing %s " $source
	[[ -n $extra ]] && printf "%s " $extra
	printf "... "
	if ! $gas $gflags -o $outfile $source 2>$aserr >/dev/null; then
		handle_failure $dir "(assembling)" $source $cmp
		return
	fi

	if ! $dt_dis $outfile >$disfile 2>$diserr; then
		handle_failure $dir "(disassembling)" $source $cmp
		return
	fi

	if ! $dt_diff $disfile $cmp; then
		handle_failure $dir "(comparing)" $source $cmp
		return
	fi

	((dt_tsuc++))
	print "passed"
	rm -rf $dir || fatal "failed to remove directory $dir"
}

#
# Run a single test. This may result in two actual tests (one 32-bit and one
# 64-bit) being run.
#
run_single_file()
{
	typeset sfile base cmpfile prefix arch gas p flags
	typeset asflags32 asflags64
	sfile=$1

	base=${sfile##*/}
	cmpfile=${sfile%.*}.out
	prefix=${base%%.*}
	arch=${sfile%/*}
	arch=${arch##*/}
	[[ -f $cmpfile ]] || fatal "missing output file $cmpfile"
	gas=${dt_platforms[$arch]}
	[[ -n $gas ]] || fatal "encountered test $sfile, but missing assembler"

	case "$arch" in
	"risc-v")
		asflags32="-march=rv32g"
		asflags64="-march=rv64g"
		;;
	"risc-v-c")
		asflags32="-march=rv32gc"
		asflags64="-march=rv64gc"
		;;
	*)
		asflags32="-32"
		asflags64="-64"
		;;
	esac

	case "$prefix" in
	32)
		test_one $asflags32 $sfile $cmpfile
		;;
	64)
		test_one $asflags64 $sfile $cmpfile
		;;
	tst)
		test_one $asflags32 $sfile $cmpfile "(32-bit)"
		test_one $asflags64 $sfile $cmpfile "(64-bit)"
		;;
	esac
}

#
# Iterate over all the test directories and run the specified tests
#
run_tests()
{
	typeset t
	if [[ $# -ne 0 ]]; then
		for t in $@; do
			run_single_file $t
		done
	else
		typeset k tests tests32 tests64
		for k in ${!dt_platforms[@]}; do
			tests=$(find $dt_root/$k -type f -name 'tst.*.s')
			tests32=$(find $dt_root/$k -type f -name '32.*.s')
			tests64=$(find $dt_root/$k -type f -name '64.*.s')
			for t in $tests $tests32 $tests64; do
				run_single_file $t
			done
		done
	fi
}

goodbye()
{
	cat <<EOF

--------------
libdis Results
--------------

Tests passed: $dt_tsuc
Tests failed: $dt_tfail
Tests ran:    $dt_tnum
EOF
}


dt_origwd=$PWD
cd $(dirname $0) || fatal "failed to cd to test root"
dt_root=$PWD
cd $dt_origwd || fatal "failed to return to original dir"

while getopts ":np:" c $@; do
	case "$c" in
	n)
		dt_nodefault="y"
		;;
	p)
		OLDIFS=$IFS
		IFS="="
		set -A split $OPTARG
		IFS=$OLDIFS
		[[ ${#split[@]} -eq 2 ]] || usage "malformed -p option: $OPTARG"
		dt_platforms[${split[0]}]=${split[1]}
		;;
	:)
		usage "option requires an argument -- $OPTARG"
		;;
	*)
		usage "invalid option -- $OPTARG"
		;;
	esac
done

[[ -n $dt_nodefault && ${#dt_platforms[@]} -eq 0 ]] && fatal \
    "no platforms specified to run tests for"

shift $((OPTIND-1))

determine_arch
check_platforms
run_tests
goodbye

[[ $dt_tfail -eq 0 ]]
