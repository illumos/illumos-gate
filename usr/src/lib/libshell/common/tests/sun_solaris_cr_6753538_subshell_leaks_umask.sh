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
# Test whether CR #6753538 ("umask modification leaks out of a ksh93
# subshell") has been fixed.
#
# Quote from CR #6753538: 
# -- snip --
# I discovered that Solaris 11's /bin/sh exhibits the following
# surprising behavior:
#
#    $ /bin/sh -c 'umask 22; (umask 0); umask'
#    0000
#
# All other shells I tried print 22.
# -- snip --


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
# test set 1: Simple umask in subshell
#
x=$(${SHELL} -c 'umask 22; (umask  0); umask') 
[[ "$x" == "0022" ]] || err_exit "expected umask 0022, got $x"

x=$(${SHELL} -c 'umask 20; (umask  0); umask')
[[ "$x" == "0020" ]] || err_exit "expected umask 0020, got $x"

x=$(${SHELL} -c 'umask  0; (umask 22); umask')
[[ "$x" == "0000" ]] || err_exit "expected umask 0000, got $x"


#
# test set 2: Simple umask in two subshells
#
x=$(${SHELL} -c 'umask 22; ( (umask 10); umask  0); umask')
[[ "$x" == "0022" ]] || err_exit "expected umask 0022, got $x"

x=$(${SHELL} -c 'umask 20; ( (umask 10); umask 0); umask')
[[ "$x" == "0020" ]] || err_exit "expected umas k 0020, got $x"

x=$(${SHELL} -c 'umask  0; ( (umask 10); umask 22); umask')
[[ "$x" == "0000" ]] || err_exit "expected umask 0000, got $x"


#
# test set 3: Compare normal subshell vs. subshell in seperate process
# ($ ulimit -c 0 # forced the subshell to |fork()|
#
x=$(${SHELL} -c 'umask 22; (              umask  0); umask') || err_exit "shell failed."
y=$(${SHELL} -c 'umask 22; (ulimit -c 0 ; umask  0); umask') || err_exit "shell failed."
[[ "$x" == "$y" ]] || err_exit "$x != $y"

x=$(${SHELL} -c 'umask 20; (              umask  0); umask') || err_exit "shell failed."
y=$(${SHELL} -c 'umask 20; (ulimit -c 0 ; umask  0); umask') || err_exit "shell failed."
[[ "$x" == "$y" ]] || err_exit "$x != $y"

x=$(${SHELL} -c 'umask  0; (              umask 20); umask') || err_exit "shell failed."
y=$(${SHELL} -c 'umask  0; (ulimit -c 0 ; umask 20); umask') || err_exit "shell failed."
[[ "$x" == "$y" ]] || err_exit "$x != $y"


# tests done
exit $((Errors))
