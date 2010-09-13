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
# primenumbers1 - a simple prime number generator
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


# check whether arg1 is a prime number via comparing it against the "pn" array
function is_prime
{
	integer i
	integer num=$1
	float   max_pn

	(( max_pn=sqrt(num)+1. ))
    
	for (( i=0 ; i < num_pn && pn[i] < max_pn ; i++)) ; do
		(( num % pn[i] == 0 )) && return 1;
	done
	return 0
}

# main
set -o errexit

# get arguments
integer max_prime=$1 # maximum prime number
typeset outputformat=$2

# variables
integer -a pn		# integer array for the prime numbers
integer num_pn=1	# number of prime numbers
integer n		# current number which should be tested
pn[0]=2			# start value

# prechecks
(( max_prime > 1 )) || { print -u2 -f "%s: requires a positive integer as first input.\n" "$0" ; exit 1 ; }

# calculate prime numbers
printf $"# %s: Calculating prime numbes from 1 to %i\n" "${ date '+%T' ; }" max_prime 1>&2

for (( n=3 ; n < max_prime ; n+=2 )) ; do
	if is_prime $n ; then
		(( pn[num_pn++]=n ))
	fi
done

# print results
printf $"# %s: Calculation done, printing results:\n" "${ date '+%T' ; }" 1>&2

for (( n=0 ; n < num_pn ; n++ )) ; do
	# print prime number
	case ${outputformat} in
		block)
			printf $"%i$( (( n % 8 == 0 )) && print -r '\n' || print -r ',\t')" pn[n]
			;;
		line)
			printf $"%i\n" pn[n]
			;;
		*)
			printf $"prime %i:\t%i\n" n pn[n]
			;;
	esac
done

if [[ ${outputformat} == "block" ]] && (( n % 8 != 1 )); then
	print
fi

printf $"# %s: Done.\n" "${ date '+%T' ; }" 1>&2

#EOF.
