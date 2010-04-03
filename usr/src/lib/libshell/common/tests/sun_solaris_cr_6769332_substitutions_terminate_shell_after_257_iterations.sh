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
# This test checks whether ksh93 supports more than 256 recursive
# function+command substitution calls.
#
# This was reported as CR #6769332 ('Recursive function+command
# substitutions terminate shell after 257 iterations'):
# ------------ snip ------------
# Recursive function+command substitutions
# (e.g. func1() { x=$( func2 ) ; } ; x=$( func1 ) ) terminate the
# ksh93 shell after 257 iterations with a exit code of "0" (it
# seems the shell just "quits" after the last "return 0" statement
# in the function).
# Running the attached testcase terminates the shell after 257
# iterations (g=257 in the script) while 256 iterations (replace
# "257" with "256" in the script) just works fine.
# The same testcase works Ok in ksh88 (=/usr/bin/ksh in
# Solaris 10U5)
#
# Expected Result
#    The script should output "done" and return the exit code 0.
#
# Actual Result
#    No messsge. Exit code "0".
#
# Error Message(s)
#    None (exit code is "0").
#
# Test Case
#    f1()
# {
#         h=$1
#         (( h=h-1 ))
#         (( h <= 0 )) && return 0
#         x=$(f1 "$h" "$l" "$g" d e "$l") || print -u2 "$g/$h: fail"
#         return 0
# }
# l=""
# g=257
# i=0
# while (( i < $g )) ; do
#         l="${l}x"
#         (( i=i+1 ))
# done
# f1 "$g" "$l" "$g" d e "$l" || print -u2 "$g: fail0"
# print "done"
# exit 0
#
# Workaround
#    -
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

#
# test1: Testcase from CR #6769332 
#
(
cat <<EOF
# make sure we have enougth stack (needed for 64bit SPARC and SystemZ)
ulimit -s 65536

f1()
{
        h=\$1
        (( h=h-1 ))
        (( h <= 0 )) && return 0
        x=\$(f1 "\$h" "\$l" "\$g" d e "\$l") || print -u2 "\$g/\$h: fail"
        return 0
}
l=""
g=257
i=0
while (( i < \$g )) ; do
        l="\${l}x"
        (( i=i+1 ))
done
f1 "\$g" "\$l" "\$g" d e "\$l" || print -u2 "\$g: fail0"
print "done"
EOF
) | out="$( ${SHELL} 2>&1 ; )" || err_exit "Shell returned non-zero exit code $?."

[[ "${out}" == "done" ]] || err_exit "Output expected to be 'done', got '${out}'."


# tests done
exit $((Errors))
