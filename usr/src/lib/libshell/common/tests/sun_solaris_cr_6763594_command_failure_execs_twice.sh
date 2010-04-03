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
# Test whether CR #6763594 ('ksh93 executes command after "command"
# builtin twice on failure') has been fixed.
#
# Quote from CR #6763594: 
# ---- snip ----
# ksh93 has a bug which causes shell to execute the command after the
# "command" builtin to be executed twice if "command" fails:
# -- snip --
# $ ksh93 -x -c 'print "true" >myfoo ; chmod a+x,a-r myfoo ; command ./myfoo ;
# print $?'
# + print true
# + 1> myfoo
# + chmod a+x,a-r myfoo
# + command ./myfoo
# ksh93[1]: ./myfoo: ./myfoo: cannot open [Permission denied]
# + print 1
# 1
# + print 0
# 0
# -- snip --
# The "print" command at the end is executed twice in this case since
# the shell jumps to the wrong position in the execution sequence.
#
# The correct output should be:
# -- snip --
# $ ksh93 -x -c 'print "true" >myfoo ; chmod a+x,a-r myfoo ; command ./myfoo ;
# print $?'
# + print true
# + 1> myfoo
# + chmod a+x,a-r myfoo
# + command ./myfoo
# ksh93[1]: ./myfoo: ./myfoo: cannot open [Permission denied]
# + print 1
# 1
# -- snip --
# ---- snip ----


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


typeset testtmpdir=/tmp/ksh93_test_cr_6763594_${PPID}_$$
mkdir "${testtmpdir}" || { err_exit "Could not create temporary directory ${testtmpdir}." ; exit ${Errors} ; }

cd "${testtmpdir}" || { err_exit "Cannot cd to temporary directory ${testtmpdir}." ; exit ${Errors} ; }

typeset s

${SHELL} -c 'print "true" >myfoo ; chmod a+x,a-r myfoo ; command ./myfoo ; print $?' 1>out_stdout 2>out_stderr
(( $? == 0 )) || err_exit "Return code $?, expected 0"

s=$( < out_stdout ) ; [[ "$s" == '126' ]] || err_exit "Expected '126', got $(printf "%q\n" "$s")."
s=$( < out_stderr ) ; [[ "$s" == ~(Elr)(.*:\ \./myfoo:\ \./myfoo:\ .*\[.*\]) ]] || err_exit "Output $(printf "%q\n" "$s") does not match pattern '~(Elr)(.*:\ \./myfoo:\ \./myfoo:\ .*\[.*\])'."

rm "myfoo" "out_stdout" "out_stderr" || err_exit "rm failed."
cd ..
rmdir "${testtmpdir}" || err_exit "Failed to remove temporary directory ${testtmpdir}."


# tests done
exit $((Errors))
