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
# This test checks whether the Solaris kernel can directly execute compiled
# shell code.
#
# This was reported as CR #6862121 ("shbinexec kernel module defunct"):
# ------------ snip ------------
# [Originally reported by Sun Japan]
# The new shbinexec kernel module added in B106 is defunct, originally
# caused by my mismerge of the original development tree and later
# because the matching test module didn't test it correctly (April
# quickly discovered the problem but the issue drowned in the cleanup
# putbacks ).
# Frequency
#    Always
# Regression
#    No
# Steps to Reproduce
#    $ cat test1.sh                                                                                                   
# print hello
# printf "args=%s\n" "$@"
# $ shcomp test1.sh test1
# # note: this MUST be bash since ksh93 has special support for compiled shell
# # scripts which causes the kernel module to be bypassed (that's why the tes
# # never worked)
# $ bash -c './test1 "a b" "c" "d"'
# Expected Result
#    hello                                                
# args=a a1
# args=b
# args=c
# Actual Result
#    ./test1: line 1: a: not found
# Error Message(s)
#    ./test1: line 1: a: not found
# Test Case
#    See above.
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
tmpdir="$(mktemp -t -d "test_sun_solaris_cr_6862121_shbinexec_kernel_module_defunct.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }


# run tests
{
cat <<EOF
	print hello
	printf "args=%s\n" "\$@"
EOF
} >script1.sh

# Compile script (note we use the platform's /usr/bin/shcomp, _not_ ${SHCOMP})
/usr/bin/shcomp "script1.sh" "script1" || err_exit "shcomp failed with error=$?"

[[ -x "./script1" ]] || err_exit "Script script1 not executable"
out="$(/usr/bin/bash -c './script1 a b "c d"' 2>&1 )" || err_exit "Compiled script failed to execute, error=$?"
[[ "${out}" == $'hello\nargs=a\nargs=b\nargs=c d' ]] || err_exit "Expected xxx, got $(printf "%q\n" "$out")"

# cleanup
rm "script1" "script1.sh"
cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
