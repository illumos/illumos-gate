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
# This test checks whether the AST "cut" utility's "-d" option
# works with multibyte characters
#
# This was reported as CR #6904575 ("cut -d with multibyte character no longer works"):
# ------------ snip ------------
# cut -d with multibyte char no longer work correctly.
# 
# $ echo $LANG
# ja
# $ od -tx1 mb.eucjp                  
# 0000000 a4 a2 a4 a4 a4 a4 a4 a6 a4 a8 0a
# 0000013
# $ od -tx1 delim                     
# 0000000 a4 a4 0a
# 0000003
# $ wc -m mb.eucjp
#        6 mb.eucjp
# 
# It has 5 characters (2byte each).
# 
# $ /usr/bin/cut -d `cat delim` -f1 mb.eucjp | od -tx1                          
# 0000000 0a
# 0000001
# 
# correct output is
# 
# 0000000 a4 a2 0a
# 0000003
# 
# files are attached.
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

typeset ocwd
typeset tmpdir
typeset out

# create temporary test directory
ocwd="$PWD"
tmpdir="$(mktemp -t -d "test_sun_solaris_cr_6904575_cut_-d_with_multibyte_character_no_longer_works.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }


# run tests


function test1
{
	typeset cut_cmd="$1"
	typeset testid
	typeset out
	typeset testname
	compound saved_locale
	
	# save locale information
	[[ -v LC_ALL	]] && saved_locale.LC_ALL="${LC_ALL}"
	[[ -v LC_CTYPE	]] && saved_locale.LC_CTYPE="${LC_CTYPE}"
	[[ -v LANG	]] && saved_locale.LANG="${LANG}"

	compound -r -a testcases=(
		(
			typeset name="ascii_plain"
			typeset locale="C"
			typeset input_format='abcdefg'
			typeset -a cut_args_format=( "-f1" "-d" "e" )
			typeset output_format='abcd'
		)
		(
			typeset name="unicode_plain"
			typeset locale="<unicode>"
			typeset input_format='abcd\u[20ac]fg'
			typeset -a cut_args_format=( '-f1' '-d' '\u[20ac]' )
			typeset output_format='abcd'
		)
		(
			typeset name="unicode_plain2"
			typeset locale="<unicode>"
			typeset input_format='abcd\u[20ac]fg'
			typeset -a cut_args_format=( '-f1' '-d' 'f' )
			typeset output_format='abcd\u[20ac]'
		)
	)

	for testid in "${!testcases[@]}" ; do
        	nameref tc=testcases[${testid}]
		testname="${cut_cmd}/${tc.name}"

		if [[ "${tc.locale}" == "<unicode>" ]] ; then
			if [[ "$LC_ALL" != *.UTF-8 ]] ; then
				export LC_ALL='en_US.UTF-8'
			fi
		else
			export LC_ALL="${tc.locale}"
		fi
		
		# build "cut_args" array with multibyte characters in the current locale
		typeset -a cut_args
		integer arg_index
		for arg_index in "${!tc.cut_args_format[@]}" ; do
			cut_args+=( "$( printf -- "${tc.cut_args_format[arg_index]}" )" )
		done
		
		typeset output_format="$( printf -- "${tc.output_format}" )"
		
		#printf "args=|%q|\n" "${cut_args[@]}"

		out="$(printf "${tc.input_format}" | ${SHELL} -c "${cut_cmd} \"\$@\"" dummy "${cut_args[@]}" 2>&1)" || err_exit "${testname}: Command returned exit code $?"
		[[ "${out}" == ${output_format} ]] || err_exit "${testname}: Expected match for $(printf "%q\n" "${output_format}"), got $(printf "%q\n" "${out}")"

		# cleanup and restore locale settings
		unset cut_args arg_index
		[[ -v saved_locale.LC_ALL	]] && LC_ALL="${saved_locale.LC_ALL}" || unset LC_ALL
		[[ -v saved_locale.LC_CTYPE	]] && LC_CTYPE="${saved_locale.LC_CTYPE}" || unset LC_CTYPE
		[[ -v saved_locale.LANG		]] && LANG="${saved_locale.LANG}" || unset LANG
	done

	return 0
}


function test2
{
	typeset cutcmd=$1
	typeset testname="${cutcmd}"
	typeset out

	# create files
	printf "\xa4\xa2\xa4\xa4\xa4\xa4\xa4\xa6\xa4\xa8\x0a" >"mb.eucjp"
	printf "\xa4\xa4\x0a" >"delim"

	# run test
	out=$( LC_ALL=ja_JP.eucJP ${SHELL} -o pipefail -o errexit -c '$1 -d $(cat delim) -f1 "mb.eucjp" | od -tx1' dummy "${cutcmd}" 2>&1 ) || err_exit "${testname}: Test failed with exit code $?"
	[[ "${out}" == $'0000000 a4 a2 0a\n0000003' ]] || err_exit "${testname}: Expected \$'0000000 a4 a2 0a\n0000003', got $(printf "%q\n" "${out}")"

	# cleanup
	rm "mb.eucjp" "delim"

	return 0
}

#for cmd in "/usr/bin/cut" "cut" ; do
for cmd in "cut" ; do
	test1 "${cmd}"
	test2 "${cmd}"
done



cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
