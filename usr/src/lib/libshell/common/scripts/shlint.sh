#!/usr/bin/ksh93

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
# shlint - a simple lint wrapper around "shcomp"
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# Make sure all math stuff runs in the "C" locale to avoid problems
# with alternative # radix point representations (e.g. ',' instead of
# '.' in de_DE.*-locales). This needs to be set _before_ any
# floating-point constants are defined in this script).
if [[ "${LC_ALL}" != "" ]] ; then
    export \
        LC_MONETARY="${LC_ALL}" \
        LC_MESSAGES="${LC_ALL}" \
        LC_COLLATE="${LC_ALL}" \
        LC_CTYPE="${LC_ALL}"
        unset LC_ALL
fi
export LC_NUMERIC=C

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${shlint_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename

typeset progname="${ basename "${0}" ; }"

typeset -r shlint_usage=$'+
[-?\n@(#)\$Id: shlint (Roland Mainz) 2009-03-15 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?shlint - lint for POSIX shell scripts]
[+DESCRIPTION?\bshlint\b is a lint for POSIX shell scripts.]
[+SEE ALSO?\bshcomp\b(1), \bksh93\b(1)]
'

while getopts -a "${progname}" "${shlint_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)    usage ;;
	esac
done
shift $((OPTIND-1))

(( $# > 0 )) || usage

file="$1"
[[ ! -f "$file" ]] && fatal_error $"File ${file} not found."
[[ ! -r "$file" ]] && fatal_error $"File ${file} not readable."

x="$( /usr/bin/shcomp -n "${file}" /dev/null 2>&1 1>/dev/null  )"

printf "%s\n" "$x"

[[ "$x" != "" ]] && exit 1 || exit 0
# EOF.
