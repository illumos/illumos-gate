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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test checks whether the issue described in CR #6687139
# ("command substitution, exec, and stdout redirection cause
# allocation loop") has been fixed:
# -- snip --
# The following one-liner (including back ticks) causes ksh93 to spin
# out of control consuming all memory at a *very* rapid pace:
#  
#    `exec program > file`
#    
#  If "file" is a real file (as opposed to /dev/null), the file will 
#  also grow without bound.  "program" need not exist, i.e. 
#
#    `exec > file`
#
#  has the same result.  Using $() instead of `` also has the same 
#  effect.
#
#  This works fine under all other bourne-compatible shells.
# -- snip --
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

function isvalidpid
{
	kill -0 ${1} 2>/dev/null && return 0
	return 1
}

integer childpid
typeset testdir
integer childretval

testdir="/tmp/sun_solaris_cr_6687139_pid$$_${PPID}"
mkdir -p "${testdir}" || err_exit "Cannot create test dirctory"
cd "${testdir}" || { err_exit "Cannot cd to test dirctory" ; exit $Errors ; }

##############################################################################
##
## test variant 1a: Use command substitution $( ... )
##

# Run testcase with "nice" to make sure a "runaway" process can
# still be caught&&terminated by the current shell
nice -n 10 ${SHELL} -c 'touch z ; $(exec nosuchprogram_for_cr_6687139 > z) ; rm z' 2>/dev/null &
childpid=$!

sleep 5

if isvalidpid ${childpid} ; then
	# First _stop_, then log error since the child may eat up memory
	# VERY VERY quickly
	kill -STOP ${childpid}

	err_exit "Child still active after 5 seconds (hang ?)"
	
	# Get sample stack trace
	pstack ${childpid}
	kill -KILL ${childpid}
fi

# collect child's return status
wait ${childpid}
childretval=$?

(( childretval == 0 )) || err_exit "Child returned non-zero exit code ${childretval}."

[[ ! -f "z" ]] || { rm "z" ; err_exit "Child did not remove test file" ; }


##############################################################################
##
## test variant 1b: Same as test 1a but forces the shell to |fork()| for the
## subshell
##

# Run testcase with "nice" to make sure a "runaway" process can
# still be caught&&terminated by the current shell
nice -n 10 ${SHELL} -c 'touch z ; $(ulimit -c 0 ; exec nosuchprogram_for_cr_6687139 > z) ; rm z' 2>/dev/null &
childpid=$!

sleep 5

if isvalidpid ${childpid} ; then
	# First _stop_, then log error since the child may eat up memory
	# VERY VERY quickly
	kill -STOP ${childpid}

	err_exit "Child still active after 5 seconds (hang ?)"
	
	# Get sample stack trace
	pstack ${childpid}
	kill -KILL ${childpid}
fi

# collect child's return status
wait ${childpid}
childretval=$?

(( childretval == 0 )) || err_exit "Child returned non-zero exit code ${childretval}."

[[ ! -f "z" ]] || { rm "z" ; err_exit "Child did not remove test file" ; }


##############################################################################
##
## test variant 2a: Use plain subshell ( ... )
##

# Run testcase with "nice" to make sure a "runaway" process can
# still be caught&&terminated by the current shell
nice -n 10 ${SHELL} -c 'touch z ; (exec nosuchprogram_for_cr_6687139 > z) ; rm z' 2>/dev/null &
childpid=$!

sleep 5

if isvalidpid ${childpid} ; then
	# First _stop_, then log error since the child may eat up memory
	# VERY VERY quickly
	kill -STOP ${childpid}

	err_exit "Child still active after 5 seconds (hang ?)"
	
	# Get sample stack trace
	pstack ${childpid}
	kill -KILL ${childpid}
fi

# collect child's return status
wait ${childpid}
childretval=$?

(( childretval == 0 )) || err_exit "Child returned non-zero exit code ${childretval}."

[[ ! -f "z" ]] || { rm "z" ; err_exit "Child did not remove test file" ; }


##############################################################################
##
## test variant 2b: Same as test 2a but forces the shell to |fork()| for the
## subshell
##

# Run testcase with "nice" to make sure a "runaway" process can
# still be caught&&terminated by the current shell
nice -n 10 ${SHELL} -c 'touch z ; (ulimit -c 0 ; exec nosuchprogram_for_cr_6687139 > z) ; rm z' 2>/dev/null &
childpid=$!

sleep 5

if isvalidpid ${childpid} ; then
	# First _stop_, then log error since the child may eat up memory
	# VERY VERY quickly
	kill -STOP ${childpid}

	err_exit "Child still active after 5 seconds (hang ?)"
	
	# Get sample stack trace
	pstack ${childpid}
	kill -KILL ${childpid}
fi

# collect child's return status
wait ${childpid}
childretval=$?

(( childretval == 0 )) || err_exit "Child returned non-zero exit code ${childretval}."

[[ ! -f "z" ]] || { rm "z" ; err_exit "Child did not remove test file" ; }

# tests done, remove temporary test subdir
cd /tmp
rmdir "${testdir}" || err_exit "Could not remove temporary test directory ${testdir}"


# tests done
exit $((Errors))
