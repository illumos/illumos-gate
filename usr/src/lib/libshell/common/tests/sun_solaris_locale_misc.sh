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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test module contains misc l10n tests
#
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

typeset ocwd
typeset tmpdir

# create temporary test directory
ocwd="$PWD"
tmpdir="$(mktemp -t -d "test_sun_solaris_locale_misc.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }

#
# utility functions
#

function string_has_multibyte_characters
{
	typeset str="$1"
	integer bytecount
	integer mbcharactercount
	
	(( mbcharactercount=$(LC_ALL="en_US.UTF-8" wc -C <<<"${str}") ))
	(( bytecount=$(wc -c <<<"${str}") ))
	
	(( bytecount != mbcharactercount )) && return 0
	return 1
}

#
# test functions
#

# test whether LC_ALL correctly overrides LC_MESSAGES in the choice of the system message
# catalog
# 1. This test assumes that the machine has ko_KR.UTF-8 + matching message catalogs installed
# 2. We run this test in a |fork()|'ed subshell to isolate it from the other tests
function test_lc_all_override1
{
	typeset out

	(
		ulimit -c 0 # force ksh93 to |fork()| for this subshell

		unset ${!LC_*} LANG
		#export LANG=en_US.UTF-8
		export LC_ALL="en_US.UTF-8"

		integer ch_val
		integer korean_count=0
		${SHELL} -c 'LC_MESSAGES=C ${SHELL} -c "cd no_dir_llkk ; export LC_ALL="ko_KR.UTF-8" ; cd "no_dir_ooo" ; true"' >"out" 2>&1  || err_exit "Test shell failed with non-zero exit code $?"

		while read -N1 c ; do 
			(( ch_val='${c} ))

			(( ch_val >= 0xac00 && ch_val <= 0xdfff )) && (( korean_count++ ))
		done <"out"

		# Solaris 11/B110 returns 13 characters for this test
		(( korean_count >= 10 )) || err_exit "Expected at least 10 korean characters, got ${korean_count}"
		
		rm "out"

		exit $((Errors))
	)
	(( Errors += $? ))
	return 0
}

# test whether the shell internally selects the correct message catalogs
# when the value of LC_* or LANG is restored to a "previous" value (e.g.
# subshell, function) or gets "reset" (e.g. unset)
function test_lc_l10n_scope1
{
	compound -r -a testgroups=(
		(
			name="subshell"
			typeset -a tests=(
				'LC_ALL="C" ;		cd "nosuchdir2" ; (LC_ALL="ja_JP.UTF-8" ;	cd "nosuchdir2") ; cd "nosuchdir2" ; true'
				'LC_MESSAGES="C" ;	cd "nosuchdir2" ; (LC_MESSAGES="ja_JP.UTF-8" ;	cd "nosuchdir2") ; cd "nosuchdir2" ; true'
				'LANG="C" ;		cd "nosuchdir2" ; (LANG="ja_JP.UTF-8" ;		cd "nosuchdir2") ; cd "nosuchdir2" ; true'
			)
		)
		(
			name="unset"
			typeset -a tests=(
				'LC_ALL="C" ;		cd "nosuchdir2" ; LC_ALL="ja_JP.UTF-8" ;	cd "nosuchdir2" ; unset LC_ALL ;	cd "nosuchdir2" ; true'
				'LC_MESSAGES="C" ;	cd "nosuchdir2" ; LC_MESSAGES="ja_JP.UTF-8" ;	cd "nosuchdir2" ; unset LC_MESSAGES ;	cd "nosuchdir2" ; true'
				'LANG="C" ;		cd "nosuchdir2" ; LANG="ja_JP.UTF-8" ;		cd "nosuchdir2" ; unset LANG ;		cd "nosuchdir2" ; true'
			)
		)
		(
			name="empty LC_xxx"
			typeset -a tests=(
				'LC_ALL="C" ;		cd "nosuchdir2" ; LC_ALL="ja_JP.UTF-8" ;	cd "nosuchdir2" ; LC_ALL="" ;		cd "nosuchdir2" ; true'
				'LC_MESSAGES="C" ;	cd "nosuchdir2" ; LC_MESSAGES="ja_JP.UTF-8" ;	cd "nosuchdir2" ; LC_MESSAGES="" ;	cd "nosuchdir2" ; true'
				'LANG="C" ;		cd "nosuchdir2" ; LANG="ja_JP.UTF-8" ;		cd "nosuchdir2" ; LANG="" ;		cd "nosuchdir2" ; true'
			)
		)
		(
			name="function"
			typeset -a tests=(
				'LC_ALL="C" ;		cd "nosuchdir2" ; function x { typeset LC_ALL="ja_JP.UTF-8" ;		cd "nosuchdir2" ; } ; x ; cd "nosuchdir2" ; true'
				'LC_MESSAGES="C" ;	cd "nosuchdir2" ; function x { typeset LC_MESSAGES="ja_JP.UTF-8" ;	cd "nosuchdir2" ; } ; x ; cd "nosuchdir2" ; true'
				'LANG="C" ;		cd "nosuchdir2" ; function x { typeset LANG="ja_JP.UTF-8" ;		cd "nosuchdir2" ; } ; x ; cd "nosuchdir2" ; true'
			)
		)
	)


	typeset tgi ti out2

	for tgi in "${!testgroups[@]}" ; do
		nameref tg=testgroups[${tgi}]

		for ti in "${!tg.tests[@]}" ; do
			nameref ts=tg.tests[${ti}]

			${SHELL} -c "unset LANG \${!LC_*} ; ${SHELL} -c \"${ts}\"" >out 2>&1 || err_exit "test returned non-zero exit code $?"
			out2="${
				while read -r line ; do
					string_has_multibyte_characters "${line}" && print -n "A" || print -n "_"
				done <"out"
				print ""
			}"
			if [[ "${out2}" != '_A_' ]] ; then
				err_exit "test '${tg.name}'/'$ts' failed: Expected '_A_', got '${out2}'"
				#cat out
			fi
		done
	done
	
	rm "out"
	
	return 0
}


# run tests
test_lc_all_override1
test_lc_l10n_scope1


cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
