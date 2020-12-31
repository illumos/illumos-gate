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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Test whether the ksh93/poll builtin works as expected
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0


builtin -f libshell.so.1 poll || err_exit "poll builtin not found."

compound d1=(
	compound -A u=(
		[y]=( fd=5 events="POLLIN" revents="" )
		[x]=( fd=5 events="POLLIN" revents="" )
	)
)

# test 1:
cat /dev/zero | { redirect 5<&0 ; poll -e d1.res -t 5. d1.u ; } || err_exit "poll returned non-zero exit code $?"
[[ "${d1.u[x].revents}" == "POLLIN" ]] || err_exit "d1.u[x].revents contains '${d1.u[x].revents}', not POLLIN"
[[ "${d1.u[y].revents}" == "POLLIN" ]] || err_exit "d1.u[y].revents contains '${d1.u[y].revents}', not POLLIN"
[[ "${d1.res[*]}" == "x y" ]] || err_exit "d1.res contains '${d1.res[*]}', not 'x y'"

# test 2:
unset d1.res

d1.u[z]=( fd=5 events="POLLOUT" revents="" )
{ poll -e d1.res -t 5. d1.u ; } 5</dev/null 5>/dev/null || err_exit "poll returned non-zero exit code $?"
[[ "${d1.u[x].revents}" == "POLLIN"             ]] || err_exit "d1.u[x].revents contains '${d1.u[x].revents}', not 'POLLIN'"
[[ "${d1.u[y].revents}" == "POLLIN"             ]] || err_exit "d1.u[y].revents contains '${d1.u[y].revents}', not 'POLLIN'"
[[ "${d1.u[z].revents}" == "POLLOUT|POLLWRNORM" ]] || err_exit "d1.u[z].revents contains '${d1.u[z].revents}', not 'POLLOUT|POLLWRNORM,'"
[[ "${d1.res[*]}" == "x y z" ]] || err_exit "d1.res contains '${d1.res[*]}', not 'x y z'"


# tests done
exit $((Errors))
