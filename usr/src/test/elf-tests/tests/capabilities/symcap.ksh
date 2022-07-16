#!/usr/bin/ksh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# souroc.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/liocnse/CDDL.
#

#
# Copyright 2022 Oxide Computer Company
#

#
# This test generates a binary with a lot of different symbol capabilities and
# then selects different capability environments to try and ensure that the
# rules for what we pick are honored.
#

export LC_ALL=C.UTF-8
unalias -a
set -o pipefail

sc_arg0=$(basename $0)
sc_err=0
sc_tmpdir=/tmp/symcap.$$
sc_prog="$sc_tmpdir/symcap"

#
# To build symbol caps, we need to annotate a .o file with object caps and then
# turn that into a symbol cap with ld. The following arrays are used to create
# this for us. sc_obj_hw1, sc_obj_hw2, and sc_obj_hw3 are the set of object
# capabilities that we want to use and then eventually turn into symbol
# capabilities. Each symbol capability prints out its own index when executed.
# This means we can see which thing ld resolved to run based on the output.
# The following summarizes our goals with each case:
#
# 0: none
# 1: only hwcap 1
# 2: only hwcap 1, but greater than (1)
# 3: only hwcap 2
# 4: only hwcap 2, but greater than (3)
# 5: only hwcap 3
# 6: only hwcap 3, but greater than (5)
# 7: uses all 3
# 8: differs from (7) in hwcap1
#
sc_obj_hw1=( "0x0" "0x5" "0x42" "0x0"  "0x0"    "0x0"     "0x0"
     "0x3"       "0x8" )
sc_obj_hw2=( "0x0" "0x0" "0x0"  "0x23" "0xff00" "0x0"     "0x0"
    "0xff7ff6"   "0xff7ff6" )
sc_obj_hw3=( "0x0" "0x0" "0x0"  "0x0"  "0x0"    "0x12345" "0x7000000"
    "0x87654321" "0x87654321" )

pass()
{
        typeset msg="$*"
	echo "TEST PASSED: $msg"
}

warn()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "TEST FAILED: $msg" >&2
	sc_err=1
}

fatal()
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$sc_arg0: $msg" >&2
        exit 1
}

cleanup()
{
	rm -rf "$sc_tmpdir"
}

sanity_check()
{
	if  (( ${#sc_obj_hw1[@]} != ${#sc_obj_hw2[@]} )); then
		fatal "sc_obj_hw1 does not match length of sc_obj_hw2"
	fi

	if  (( ${#sc_obj_hw2[@]} != ${#sc_obj_hw3[@]} )); then
		fatal "sc_obj_hw1 does not match length of sc_obj_hw2"
	fi
}

setup()
{
	typeset tolink=

	if ! mkdir "$sc_tmpdir"; then
		fatal "failed to make directory $sc_tmpdir"
	fi

	trap 'cleanup' EXIT

	cat > $sc_tmpdir/main.c <<EOF
extern void symcap_print(void);

int
main(void)
{
	symcap_print();
	return (0);
}
EOF
	if (( $? != 0 )); then
		fatal "failed to write main.c"
	fi

	tolink="$sc_tmpdir/main.c"

	for (( i = 0; i < ${#sc_obj_hw1[@]}; i++)); do
		typeset in="$sc_tmpdir/$i.c"
		typeset map="$sc_tmpdir/$i.map"
		typeset ofile="$sc_tmpdir/$i.o"
		typeset obj="$sc_tmpdir/$i.o.obj"
		typeset sym="$sc_tmpdir/$i.o.sym"

		cat > $in <<EOF
#include <stdio.h>

void
symcap_print(void)
{
	printf("%u\n", $i);
}
EOF
		if (( $? != 0 )); then
			fatal "failed to write $in"
		fi

		cat > $map <<EOF
\$mapfile_version 2
CAPABILITY {
	HW_1 += ${sc_obj_hw1[$i]};
	HW_2 += ${sc_obj_hw2[$i]};
	HW_3 += ${sc_obj_hw3[$i]};
};
EOF
		if (( $? != 0 )); then
			fatal "failed to write $map"
		fi

		#
		# There are three steps to creating a symbol capability due to
		# the world we're in. First we need to make the normal .o. Then
		# we use a mapfile to add the object caps, while reducing
		# visibility. Then we turn the object cap into a symbol cap.
		#
		if ! gcc -m64 -o $ofile -c $in; then
			fatal "failed to create object file $ofile"
		fi

		#
		# If the entry has a zero for all cases (e.g. our default case),
		# then skip the rest of this processing and append the .o.
		#
		if (( sc_obj_hw1[i] == 0 && sc_obj_hw2[i] == 0 &&
		    sc_obj_hw3[i] == 0 )); then
			tolink="$tolink $ofile"
			continue
		fi

		if ! ld -r -o $obj $ofile -M$map -Breduce; then
			fatal "failed to create object cap file $obj"
		fi

		if ! ld -r -o $sym -z symbolcap $obj; then
			fatal "failed to create symbol cap file $sym"
		fi

		tolink="$tolink $sym"
	done

	if ! gcc -m64 -o $sc_prog $tolink; then
		fatal "failed to create $sc_prog"
	fi
}

#
# Given a set of caps, indicate which index we expect to be printed out and
# check for that.
#
run_one()
{
	typeset index="$1"
	typeset caps="$2"
	typeset out=

	out=$(LD_CAP_FILES=$sc_prog LD_HWCAP="$caps" $sc_prog)
	if (( $? != 0 )); then
		warn "failed to execute $sc_prog with cap $caps"
		return
	fi

	if [[ "$out" != "$index" ]]; then
		warn "$caps had wrong output, found $out, expected $index"
	else
		pass "LD_HWCAP=$caps"
	fi
}

sanity_check
setup

#
# First, go through and verify that if we match the caps exactly for this, we'll
# choose this symbol.
#
run_one 0 "[1]0x0,[2]0x0,[3]0x0"
run_one 1 "[1]0x5,[2]0x0,[3]0x0"
run_one 2 "[1]0x42,[2]0x0,[3]0x0"
run_one 3 "[1]0x0,[2]0x23,[3]0x0"
run_one 4 "[1]0x0,[2]0xff00,[3]0x0"
run_one 5 "[1]0x0,[2]0x0,[3]0x12345"
run_one 6 "[1]0x0,[2]0x0,[3]0x7000000"
run_one 7 "[1]0x3,[2]0xff7ff6,[3]0x87654321"
run_one 8 "[1]0x8,[2]0xff7ff6,[3]0x87654321"

#
# For cases where we have multiple symbol caps at a given level, show that we
# pick a sub one when we're between the two.
#
run_one 0 "[1]0x40,[2]0x0,[3]0x0"
run_one 1 "[1]0x45,[2]0x0,[3]0x0"
run_one 1 "[1]0x45,[2]0x10,[3]0x0"
run_one 2 "[1]0x142,[2]0x10,[3]0x0"
run_one 3 "[1]0x1,[2]0x137,[3]0x0"

#
# We expect the system to pick the "best" aka highest capability. So for the
# next round we attempt to combine multiple values and see which we pick. In
# particular here we're trying to pick between things at the same level and also
# ensure we pick the one that is higher (e.g. hw3 > hw2 > hw1)
#
run_one 6 "[1]0x47,[2]0xff23,[3]0x7012345"
run_one 5 "[1]0x47,[2]0xff23,[3]0x6012345"
run_one 5 "[1]0x47,[2]0xff23,[3]0x1012345"
run_one 4 "[1]0x47,[2]0xff23,[3]0x1002345"
run_one 3 "[1]0x47,[2]0x7723,[3]0x1002345"
run_one 3 "[1]0x47,[2]0x0f23,[3]0x1002345"
run_one 3 "[1]0x47,[2]0x0023,[3]0x1002345"
run_one 2 "[1]0x47,[2]0x0003,[3]0x1002345"
run_one 2 "[1]0x46,[2]0x0003,[3]0x1002345"
run_one 1 "[1]0x35,[2]0x0003,[3]0x1002345"
run_one 1 "[1]0x15,[2]0x0003,[3]0x1002345"
run_one 0 "[1]0x10,[2]0x0003,[3]0x1002345"

#
# Finally we want a few tests that verify that when things match, the lowest bit
# of it decides.
#
run_one 8 "[1]0xb,[2]0xff7ff6,[3]0x87654321"
run_one 8 "[1]0x3b,[2]0xff7ff6,[3]0x87654321"
run_one 8 "[1]0xffffffff,[2]0xffffffff,[3]0xffffffff"
run_one 7 "[1]0xfffffff7,[2]0xffffffff,[3]0xffffffff"

exit $sc_err
