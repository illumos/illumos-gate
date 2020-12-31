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
# This test checks whether ksh93 does unneccesaty |libc::getpwnam()|
# calls for "~(modifer)pattern"-style shell patterns
#
# This was reported as CR #6807179 ("ksh93 does unneccesary |libc::getpwnam()| lookups for ~(modifier) pattern patterns"):
# ------------ snip ------------
# ksh93 does unneccesary |libc::getpwnam()| lookups for
# ~(modifer)pattern patterns, e.g. [[ $foo == ~(E)hello.*world ]].
# The problem is that the shell ~(modifer)pattern is an extended
# pattern syntax which allows to specify a "modifer" to change
# the behaviour for "pattern". However the '~' at the beginning
# of this string is causing a tilde expansion (or better: It's
# filling an internal buffer as preparation for tilde expansion
# and this code calls |libc::getpwnam()|) which shouldn't be
# done in this case.
# [1]=For example the "modifer" allows to specifcy "perl",
# "fgrep", "grep", "egrep", "POSIX shell", "korn shell" and
# other types of pattern matching systems (or select stuff
# like archors, case-insensitive matching etc. etc.).
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

typeset tmpfile

tmpfile="$(mktemp -t "sun_solaris_cr_6807179_shellpattern_uses_getpwnam.${PPID}.$$.XXXXXX")" || err_exit "Cannot create temporary file."
rm -f "${tmpfile}"


# test 1: Check if the shell uses |libc::getpwnam()| for pattern "~(Elr)wo.*ld"
truss -u :: -o "${tmpfile}" ${SHELL} -c '[[ ${hello} == ~(Elr)wo.*ld ]] ; true' || err_exit "truss returned failure=$?"
[[ "$( < "${tmpfile}")" != *getpwnam* ]] || err_exit "truss log reports the use of getpwnam() for pattern ~(Elr)wo.*ld"
rm "${tmpfile}" || err_exit "rm ${tmpfile} failed."


# test 2: Check if the shell uses |libc::getpwnam()| for pattern "~(Si)wo*ld"
truss -u :: -o "${tmpfile}" ${SHELL} -c '[[ ${hello} == ~(Si)wo*ld ]] ; true' || err_exit "truss returned failure=$?"
[[ "$( < "${tmpfile}")" != *getpwnam* ]] || err_exit "truss log reports the use of getpwnam() for pattern ~(Si)wo*ld"
rm "${tmpfile}" || err_exit "rm ${tmpfile} failed."


# test 3: Same as test 1 but uses ~root/ as pattern which will force the use of |libc::getpwnam()|
getent passwd root >/dev/null || err_exit "getent passwd root failed" # safeguard to make sure we get a warning if user root is missing

truss -u :: -o "${tmpfile}" ${SHELL} -c '[[ ${hello} == ~root/ ]] ; true' || err_exit "truss returned failure=$?"
[[ "$( < "${tmpfile}" )" == *getpwnam* ]] || err_exit "truss log reports the use of getpwnam() for pattern ~root/"
rm "${tmpfile}" || err_exit "rm ${tmpfile} failed."


# tests done
exit $((Errors))
