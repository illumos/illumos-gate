#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

usage() {
	cat 1>&2 << 'EOF'
usage: whocalls [sl:] <funcname> <utility> [utility arguments]

  whocalls will audit all function bindings between <utility> and any library
  it utilizes.  Each time the function <funcname> is called, a stack
  backtrace is displayed

	-l <wholib>
		specify an alternate who.so to use.

	-s	When available, examine and use the .symtab symbol table
		for local symbols (more expensive).
EOF
}

optlet="sl:"

if [[ $# -lt 2 ]]; then
	usage
	exit 1
fi

wholib32="/usr/lib/link_audit/32/who.so.1"
wholib64="/usr/lib/link_audit/64/who.so.1"
detail=""

while getopts $optlet c
do
	case $c in
	l)
		wholib32="$OPTARG"
		wholib64="$OPTARG"
		;;
	s)
		detail="1"
		;;
	\?)
		usage
		exit 1
		;;
	esac
done

shift `expr $OPTIND - 1`
func=$1
shift 1

LD_AUDIT_32="$wholib32" \
LD_AUDIT_64="$wholib64" \
WHO_DETAIL="$detail" \
WHOCALLS="$func" \
"$@"
exit 0
