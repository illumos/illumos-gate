#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test checks whether the return code of a child process
# is reported properly.
#
# This was reported as CR #6887363 ("Korn shell 93 sometimes
# mishandles return value of its child process"):
# ------------ snip ------------
# Following construction sometimes ends with wrong return value.
# 
#      56 	 echo $op | grep rand 2>&1 >/dev/null
#      57 	 if [ $? = 0 ]; then
#      58 		randseq="rand${SEED}"
#      59 	 else
#      60 		randseq="seq"
#      61 	 fi
# 
# Sometimes, the given result is "rand..." even when there is
# no "rand" word in $op. This can be demonstrated with
# TSufs/SnapShots/Func test case which excercises shown code
# quite often.
# 
# As it happens only sometimes, I suppose there is an
# race-condition in handling return value from a child process.
# ------------ snip ------------
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0

typeset ocwd
typeset tmpdir
typeset out

# create temporary test directory
ocwd="$PWD"
tmpdir="$(mktemp -t -d "test_sun_solaris_cr_6887363_shell_sometimes_mishandles_return_value_of_its_child_process.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }


# run tests

# print test case from bug that ksh93 can read this script via stdin
function cat_test
{
cat <<EOF
#!/bin/sh
#
# Test derived from Sun's SnapShots Functional Suite
# 

export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# WARNING: make sure "expr" and "grep" are _external_ commands in this test

# start test
_pcnt=0

PASS(){
	_pcnt=\`/usr/bin/expr \$_pcnt + 1\`
	true
}

doblockstamper() {
	output=\`/usr/bin/sleep .01\`
	_status=\$?

	PASS "Here I am"
}

lotsaFiles() {
	OPS="read-seq read-rand syncread-seq syncread-seq"
	echo \$OPS
	for op in \$OPS; do
	 echo \$op
	 echo \$op | /usr/bin/grep rand 2>&1 >/dev/null
	 status=\$?
	 if [ \$status = 0 ]; then
		randseq="rand"
		phrase="read-rand"
	 else
		randseq="seq"
		phrase="read-seq"
	 fi
	 retcode=\$status

	 echo \$op | /usr/bin/grep sync 2>&1 >/dev/null
	 status=\$?
	 if [ \$status = 0 ]; then
		syncasync="sync"
		phrase="sync\$phrase"
	 else
		syncasync="async"
	 fi
	 retcode=\${status}-\${retcode}

	if [ "\$op" != "\$phrase" ]; then
		echo "Bad mode: \$op != \$phrase (\$retcode)"
		exit 2
	fi

	 for sz in 1 2 3 4; do
	   for type in 1 2 3 4; do
		PASS "Something"
		doblockstamper &
	   done
	   wait # Let a few finish
	 done
	done

	wait    # Make sure everyone got done

	PASS "lotsafiles \$1 \$fill"
}

cycle=0
while [ cycle -lt 24 ]; do
	cycle=\`/usr/bin/expr \$cycle + 1\`

	lotsaFiles write
	lotsaFiles write
	lotsaFiles write

	lotsaFiles read
	lotsaFiles read
	lotsaFiles read

	PASS "Cycle"
done
exit 0
EOF
}

# FIXME: we reset the VMALLOC_OPTIONS (and the depreciated VMDEBUG (for now)) variable for the run to avoid
# that the test may run for hours. This may require re-investigation why this happens.
out="$(unset VMALLOC_OPTIONS VMDEBUG ; cat_test | ${SHELL} 2>&1)" || err_exit "Unexpected exit code $?"
[[ "${out}" != "" ]] || err_exit "No output from test"

# filter output and check it
out2="$(/usr/bin/egrep -v '^((read-seq|read-rand|syncread-seq|syncread-seq)[[:space:][:blank:]]*)*$' <<<"${out}")"
[[ "${out2}" == "" ]] || err_exit "Unexpected output '${out2}'"


cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
