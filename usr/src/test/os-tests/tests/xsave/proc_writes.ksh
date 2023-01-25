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
# This shell script is a runner that tries to verify that if we write to
# a target program's xregs via /proc, that it actualy sees the same
# register contents that we put in. There are four different pieces to
# this:
#
#  o The 'proc_xregs_set' binaries which sets the registers of the target.
#    Right now we expect the bitness to match whatever it is running against.
#  o The 'xregs_dump' binaries which dump the FPU state that they have in a
#    bespoke format.
#  o The output data files that we use to try to match what is generated.
#  o The 'xsu_hwtype' binaries which tell us what data format we should expect.
#
# We have to discover what kind of hardware our target is running on and then
# that allows us to ensure that we can match up the right input and output
# files. We always run both the 32-bit and 64-bit versions of this; however,
# because 32-bit programs have access to fewer registers, they have a different
# data file to match against.
#
# We also reprat the process of 'proc_xregs_set' using the fpregs binary
# instead. That allows us to also verify some of the same behavior, but also
# pieces of fpregs functionality.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

pw_exit=0;
pw_arg0="$(basename $0)"
pw_dir="$(dirname $0)"
pw_datadir="$pw_dir/data"

#
# The starting value is used to determine the way that the regiser contents are
# set in the target's FPU. If you change this value, the check files must be
# updated.
#
typeset -A pw_start
pw_start["xregs32"]="0xc120ff06"
pw_start["xregs64"]="0xfaceecaf"
pw_start["fpregs32"]="0x20190909"
pw_start["fpregs64"]="0x28186002"

typeset -A pw_hwtypes
typeset -A pw_dump
typeset -A pw_prog
pw_hwtypes["32"]="$pw_dir/xsu_hwtype.32"
pw_hwtypes["64"]="$pw_dir/xsu_hwtype.64"
pw_dump["32"]="$pw_dir/xregs_dump.32"
pw_dump["64"]="$pw_dir/xregs_dump.64"
pw_prog["xregs32"]="$pw_dir/proc_xregs_set.32"
pw_prog["xregs64"]="$pw_dir/proc_xregs_set.64"
pw_prog["fpregs32"]="$pw_dir/fpregs.32"
pw_prog["fpregs64"]="$pw_dir/fpregs.64"

#
# All our victim programs are usually the same here and have a single breakpoint
# we want. This should become an associative array if this changes in the
# future.
#
pw_bkpt="xsu_getfpu"

warn()
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	pw_exit=1
}

run_single()
{
	typeset prog="$1"
	typeset arch="$2"
	typeset comb="$prog$arch"
	typeset fpu_type=
	typeset start=${pw_start[$comb]}
	typeset hwtype=${pw_hwtypes[$arch]}
	typeset dump=${pw_dump[$arch]}
	typeset exe=${pw_prog[$comb]}
	typeset output=
	typeset check=

	if ! fpu_type=$($hwtype 2>/dev/null); then
		warn "failed to determine $arch-bit FPU type"
		return
	fi

	printf "Discovered FPU: %s %s-bit\n" $fpu_type $arch
	output="/tmp/$prog.$fpu_type.$arch.$$"
	check="$pw_datadir/proc_writes.$prog.$fpu_type.$arch"

	if ! [[ -r $check ]]; then
		warn "missing expected output file $check"
		return;
	fi

	printf "Running %s %s %s %s\n" $exe $dump $output $start
	if ! $exe $dump $output $start $pw_bkpt; then
		warn "$exe did not execute successfully"
		rm -f $output
	fi

	if ! diff -q $check $output; then
		diff -u $check $output
		warn "$fpu_type $arch-bit FPU regs did not match expected " \
		    "output"
	else
		printf "TEST PASSED: %s %s-bit FPU regs matched /proc write\n" \
		    $fpu_type $arch
	fi

	rm -f $output
}

run_single xregs 32
run_single xregs 64
run_single fpregs 32
run_single fpregs 64

if (( pw_exit == 0 )); then
	printf "All tests passed successfully\n"
fi

exit $pw_exit
