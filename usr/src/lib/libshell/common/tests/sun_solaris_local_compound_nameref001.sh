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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# name reference test #001
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


function function2
{
	nameref v=$1
	
	v.x=19
	v.y=20
}

function function1
{
	typeset compound_var=()
	
	function2 compound_var
	
	printf "x=%d, y=%d\n" compound_var.x compound_var.y 
}

x="$(function1)"

[[ "$x" != 'x=19, y=20' ]] && err_exit "expected 'x=19, y=20', got '${x}'"


# tests done
exit $((Errors))
