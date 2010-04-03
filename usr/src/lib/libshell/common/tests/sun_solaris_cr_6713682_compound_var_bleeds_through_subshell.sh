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
# Test whether CR #6713682 has been fixed.
#
# Creating a compound variable in s subshell "bleeds through" to the calling subshell in some conditions.
# Example:
# -- snip --
# $ ksh93 -c 'unset l ; ( l=( a=1 b="BE" ) ; print "$l" ) ; print $l'
# (
#         a=1
#         b=BE
# )
# ( )
# -- snip --
# The first bracket pair is Ok since it's coming from $ print "$l" # , however the 2nd pair comes from the print $l _outside_ the subshell where the variable "l" should no longer exist.
# 
# Workaround:
# Force ksh93 to call |fork()| for the matching subshell using $ ulimit -c #, e.g. ...
# -- snip --
# $ ksh93 -c 'unset l ; ( ulimit -c 0 ; l=( a=1 b="BE" ) ; print "$l" ) ; print $l'
# (
#         a=1
#         b=BE
# )
# -- snip --
# ... provides the correct output.
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


typeset var1 var2

# use unset, l=() compound syntax and print
var1="$(${SHELL} -c 'unset l ; (               l=( a=1 b="BE" ) ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c 'unset l ; ( ulimit -c 0 ; l=( a=1 b="BE" ) ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (with unset)."

# do not use unset, l=() compound syntax and print
var1="$(${SHELL} -c '(               l=( a=1 b="BE" ) ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c '( ulimit -c 0 ; l=( a=1 b="BE" ) ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (without unset)."

# use unset, typeset -C compound syntax and print
var1="$(${SHELL} -c 'unset l ; (               compound l ; l.a=1 ; l.b="BE" ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c 'unset l ; ( ulimit -c 0 ; compound l ; l.a=1 ; l.b="BE" ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (with unset)."

# do not use unset, typeset -C compound syntax and print
var1="$(${SHELL} -c '(  	     compound l ; l.a=1 ; l.b="BE" ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c '( ulimit -c 0 ; compound l ; l.a=1 ; l.b="BE" ; print "$l" ) ; print $l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (with unset)."

# use unset, l=() compound syntax and printf "%B\n"
var1="$(${SHELL} -c 'unset l ; (               l=( a=1 b="BE" ) ; printf "%B\n" l ) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c 'unset l ; ( ulimit -c 0 ; l=( a=1 b="BE" ) ; printf "%B\n" l ) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (with unset)."

# do not use unset, l=() compound syntax and printf "%B\n"
var1="$(${SHELL} -c '(               l=( a=1 b="BE" ) ; printf "%B\n" l) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c '( ulimit -c 0 ; l=( a=1 b="BE" ) ; printf "%B\n" l) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (without unset)."

# use unset, typeset -C compound syntax and printf "%B\n"
var1="$(${SHELL} -c 'unset l ; (               compound l ; l.a=1 ; l.b="BE" ; printf "%B\n" l) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c 'unset l ; ( ulimit -c 0 ; compound l ; l.a=1 ; l.b="BE" ; printf "%B\n" l) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (with unset)."

# do not use unset, typeset -C compound syntax and printf "%B\n"
var1="$(${SHELL} -c '(  	     compound l ; l.a=1 ; l.b="BE" ; printf "%B\n" l) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
var2="$(${SHELL} -c '( ulimit -c 0 ; compound l ; l.a=1 ; l.b="BE" ; printf "%B\n" l) ; printf "%B\n" l')" || err_exit "Non-zero exit code."
[[ "${var1}" == "${var2}" ]] || err_exit "Non-fork()'ed subshell output differes from fork()'ed subshell output (with unset)."


# tests done
exit $((Errors))
