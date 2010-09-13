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
# numtree1 - basic compound variable tree demo+benchmark
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

function add_number_to_tree
{
	typeset treename=$1
	integer num=$2
	integer i
	typeset nodepath # full name of compound variable
	integer -a pe # path elements
	integer len
	typeset revnums="$(rev <<<"${num}")"

	# first built an array containing the names of each path element
	# (e.g. "135" results in an array containing "( 1 3 5 )")
	# 10#<number> is used to prevent leading zeros being interpreted
	# as octals
	for (( len=${#revnums} , i=$( printf "10#%s\n" "${revnums}" ) ; len > 0 ; len--, i=i/10 )) ; do
		pe+=( $((i % 10)) )
	done

	# walk path described via the "pe" array and build nodes if
	# there aren't any nodes yet
	nodepath="${treename}"
	for (( i=0 ; i < ${#pe[@]} ; i++ )) ; do
		nameref x="${nodepath}"
		
		# [[ -v ]] does not work for arrays because [[ -v ar ]]
		# is equal to [[ -v ar[0] ]]. In this case we can
		# use the output of typeset +p x.nodes
		[[ "${ typeset +p x.nodes ;}" == "" ]] && compound -a x.nodes
		
		nodepath+=".nodes[${pe[i]}]"
	done
	
	# insert element (leaf)
	nameref node="${nodepath}"
	[[ "${ typeset +p node.elements ;}" == "" ]] && integer -a node.elements
	node.elements+=( ${num} )

	# DEBUG only
	[[ "${!node.elements[*]}" != ""                ]] || fatal_error "assertion $LINENO FAILED"
	[[ "${ typeset +p node.elements ;}" == *-a*    ]] || fatal_error "assertion $LINENO FAILED"
	[[ "${ typeset +p node.elements ;}" == *-i*    ]] || fatal_error "assertion $LINENO FAILED"
	[[ -v node                                     ]] || fatal_error "assertion $LINENO FAILED"
	[[ -R node                                     ]] || fatal_error "assertion $LINENO FAILED"
	[[ "${ typeset +p ${!node} ;}" == *-C*         ]] || fatal_error "assertion $LINENO FAILED"
	[[ "${!x.nodes[*]}" != ""                      ]] || fatal_error "assertion $LINENO FAILED"
	[[ "${ typeset +p x.nodes ;}" == *-a*          ]] || fatal_error "assertion $LINENO FAILED"
	[[ "${ typeset +p x.nodes ;}" == *-C*          ]] || fatal_error "assertion $LINENO FAILED"
	
	return 0
}


# floating-point version of "seq"
function floatseq
{
	float i
	float arg1=$1
	float arg2=$2
	float arg3=$3

	case $# in
		1)
			for (( i=1. ; i <= arg1 ; i=i+1. )) ; do
				printf "%a\n" i
			done
			;;
		2)
			for (( i=arg1 ; i <= arg2 ; i=i+1. )) ; do
				printf "%a\n" i
			done
			;;
		3)
			for (( i=arg1 ; i <= arg3 ; i+=arg2 )) ; do
				printf "%a\n" i
			done
			;;
		*)
			print -u2 -f "%s: Illegal number of arguments %d\n" "$0" $#
			return 1
			;;
	esac
	
	return 0
}


function usage
{
	OPTIND=0
	getopts -a "${progname}" "${numtree1_usage}" OPT '-?'
	exit 2
}

# main
builtin basename
builtin rev

set -o noglob
set -o errexit
set -o nounset

compound base

compound bench=(
	float start
	float stop
)

integer i

typeset progname="${ basename "${0}" ; }"

typeset -r numtree1_usage=$'+
[-?\n@(#)\$Id: numtree1 (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?numtree1 - generate sorted variable tree containing numbers]
[+DESCRIPTION?\bnumtree1\b is a simple variable tree generator
	sorts a given set of numbers into a ksh compound variable tree).
	the application supports two different modes: \'seq\' takes
	1-3 arguments to specify the set of numbers via seq(1) and
	\'stdin\' reads the numbers from stdin (one per line)]

method [ arguments ]

[+SEE ALSO?\bksh93\b(1), \bseq\b(1)]
'

while getopts -a "${progname}" "${numtree1_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*) usage ;;
	esac
done
shift $((OPTIND-1))

# prechecks
(( $# > 0 )) || usage

cmd=$1
shift

# Read numbers from stdin outside benchmark loop
if [[ ${cmd} == 'stdin' ]] ; then
	stdin_numbers="$( cat /dev/stdin )" || fatal_error "stdin read error"
fi

(( bench.start=SECONDS ))

case ${cmd} in
	"seq")
		for i in ${ floatseq "$@" ; } ; do
			add_number_to_tree base "${i}"
		done
		;;
	"stdin")
		for i in ${stdin_numbers} ; do
			add_number_to_tree base "${i}"
		done
		;;
	"demo1")
		for i in 1 32 33 34 34 38 90 ; do
			add_number_to_tree base "${i}"
		done
		;;
	"demo2")
		for (( i=1000000000 ; i < 1000000000+10 ; i++ )) ; do
			add_number_to_tree base "$i"
		done
		;;
	*)
		fatal_error "Invalid command ${cmd}."
		;;
esac

(( bench.stop=SECONDS ))

print -u2 -f "# time used: %f\n" $((bench.stop - bench.start))

# print tree
print -v base

exit 0
# EOF.
