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
# shcalc - small shell-based calculator
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

function do_calculate
{
	typeset calcline="$1"
	float x=0.0

	printf "(( x=( %s ) ))\n" "${calcline}" | source /dev/stdin
	if (( $? != 0 )) ; then
		print -f $"%s: Syntax error in %s\n" "${progname}" "${calcline}"
		return 1
	fi

	printf "%s == %.40g\n" "${calcline}" x

	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${shcalc_usage}" OPT '-?'
	exit 2
}

# program start
# (be carefull with builtins here - they are unconditionally available
# in the shell's "restricted" mode)
builtin basename
builtin sum

typeset progname="${ basename "${0}" ; }"

typeset -r shcalc_usage=$'+
[-?\n@(#)\$Id: shcalc (Roland Mainz) 2008-11-03 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?shcalc - simple shell calculator]
[+DESCRIPTION?\bsshcalc\b is a small calculator application which
	prints the results of ISO C99 math expressions read from either
	arguments or stdin if no arguments are given.]
[+SEE ALSO?\bksh93\b(1),\bceil\b(3M), \bcopysign\b(3M), \bcos\b(3M), 
	\bcosh\b(3M), \berf\b(3M), \berfc\b(3M), \bexp\b(3M), 
	\bexp2\b(3M), \bexpm1\b(3M), \bfabs abs\b(3M), \bfdim\b(3M), 
	\bfinite\b(3M), \bfloor int\b(3M), \bfma\b(3M), \bfmax\b(3M), \bfmin\b(3M), 
	\bfmod\b(3M), \bfpclassify\b(3M), \bhypot\b(3M), \bilogb\b(3M), 
	\bisfinite\b(3M), \bisgreater\b(3M), \bisgreaterequal\b(3M), \bisinf\b(3M), 
	\bisless\b(3M), \bislessequal\b(3M), \bislessgreater\b(3M), \bisnan\b(3M), 
	\bisnormal\b(3M), \bissubnormal\b(3M), \bisunordered\b(3M), \biszero\b(3M), 
	\blgamma\b(3M), \blog\b(3M), \blog1p\b(3M), \blog2\b(3M), 
	\blogb\b(3M), \bnearbyint\b(3M), \bnextafter\b(3M), \bnexttoward\b(3M), 
	\bpow\b(3M), \bremainder\b(3M), \brint\b(3M), \bround\b(3M), 
	\bscalb\b(3M), \bscalbn\b(3M), \bsignbit\b(3M), \bsin\b(3M), 
	\bsinh\b(3M), \bsqrt\b(3M), \btan\b(3M), \btanh\b(3M), 
	\btgamma\b(3M), \btrunc\b(3M)]
'
while getopts -a "${progname}" "${shcalc_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

integer res

if (( $# == 0 )) ; then
	# No arguments ? Switch to interactive mode...
	
	# make sure "read" below uses "gmacs"-like editor keys and "multiline" mode
	
	set -o gmacs
	set -o multiline

	while read "calcline?calc> " ; do
		# quit ?
		[[ "${calcline}" == ~(Elri)(exit|quit|eof) ]] && break
		
		# empty line ?
		[[ "${calcline}" == ~(Elri)([[:space:]]*) ]] && continue
		
		do_calculate "$calcline"
		(( res=$? ))
	done

	exit ${res}
else
	while (( $# > 0 )) ; do
		do_calculate "$1"
		(( res=$? ))
		shift
	done
	
	exit ${res}
fi

# not reached

# EOF.
