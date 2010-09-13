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
# This test checks whether "wc" builtin counts the number of bytes
# and multibyte characters in different locales correctly.
#
# This was reported as CR #6904557 ("wc no longer counts number of
# bytes correctly"):
# ------------ snip ------------
# wc no longer count bytes.
# 
# $ echo $LANG
# en_US.UTF-8
# $ ls -l mb.utf8
# -rw-r--r--   1 nakanon  staff          7 Nov  2 14:06 mb.utf8
# $ wc mb.utf8
#        1       1       4 mb.utf8
# $ 
# 
# mb.utf8 is attached.
# 
# Man page says:
# 
#      If no option is  specified,  the  default  is  -lwc  (counts
#      lines, words, and bytes.)
# 
# SUS says:     
# http://www.opengroup.org/onlinepubs/000095399/utilities/wc.html
# 
# By default, the standard output shall contain an entry for each
# input file of the form:
# 
# "%d %d %d %s\n", <newlines>, <words>, <bytes>, <file>
# 
# If the -m option is specified, the number of characters shall
# replace the <bytes> field in this format.
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
tmpdir="$(mktemp -t -d "test_sun_solaris_cr_6904557_wc_no_longer_counts_number_of_bytes_correctly.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }


# run tests

function test1
{
	typeset wc_cmd="$1"
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
			typeset name="unicode_plain"
			typeset locale="<unicode>"
			typeset input_format='\xc3\xa1\xc3\xa2\xc3\xa3\x0a'
			typeset output_pattern='~(Elr)[[:space:][:blank:]]*1[[:space:][:blank:]]*1[[:space:][:blank:]]*7'
			typeset -a wc_args=( )
		)
		(
			typeset name="unicode_clw"
			typeset locale="<unicode>"
			typeset input_format='\xc3\xa1\xc3\xa2\xc3\xa3\x0a'
			typeset output_pattern='~(Elr)[[:space:][:blank:]]*1[[:space:][:blank:]]*1[[:space:][:blank:]]*7'
			typeset -a wc_args=( "-c" "-l" "-w" )
		)
		(
			typeset name="unicode_widechars_lines_words"
			typeset locale="<unicode>"
			typeset input_format='\xc3\xa1\xc3\xa2\xc3\xa3\x0a'
			typeset output_pattern='~(Elr)[[:space:][:blank:]]*1[[:space:][:blank:]]*1[[:space:][:blank:]]*4'
			typeset -a wc_args=( "-C" "-l" "-w" )
		)
		(
			typeset name="ja_JP.eucJP_plain"
			typeset locale="ja_JP.eucJP"
			typeset input_format='\x74\x32\xa1\xf7\x66\x31\x0a'
			typeset output_pattern='~(Elr)[[:space:][:blank:]]*1[[:space:][:blank:]]*1[[:space:][:blank:]]*7'
			typeset -a wc_args=( )
		)
		(
			typeset name="ja_JP.eucJP_widechars_lines_words"
			typeset locale="ja_JP.eucJP"
			typeset input_format='\x74\x32\xa1\xf7\x66\x31\x0a'
			typeset output_pattern='~(Elr)[[:space:][:blank:]]*1[[:space:][:blank:]]*1[[:space:][:blank:]]*6'
			typeset -a wc_args=( "-C" "-l" "-w" )
		)
	)

	for testid in "${!testcases[@]}" ; do
        	nameref tc=testcases[${testid}]
		testname="${wc_cmd}/${tc.name}"

		if [[ "${tc.locale}" == "<unicode>" ]] ; then
			if [[ "$LC_ALL" != *.UTF-8 ]] ; then
				export LC_ALL='en_US.UTF-8'
			fi
		else
			export LC_ALL="${tc.locale}"
		fi

		out="$(printf "${tc.input_format}" | ${SHELL} -c "${wc_cmd} \"\$@\"" dummy "${tc.wc_args[@]}" 2>&1)" || err_exit "${testname}: Command returned exit code $?"
		[[ "${out}" == ${tc.output_pattern} ]] || err_exit "${testname}: Expected match for $(printf "%q\n" "${tc.output_pattern}"), got $(printf "%q\n" "${out}")"

		# restore locale settings
		[[ -v saved_locale.LC_ALL	]] && LC_ALL="${saved_locale.LC_ALL}" || unset LC_ALL
		[[ -v saved_locale.LC_CTYPE	]] && LC_CTYPE="${saved_locale.LC_CTYPE}" || unset LC_CTYPE
		[[ -v saved_locale.LANG		]] && LANG="${saved_locale.LANG}" || unset LANG
	done

	return 0
}

#for cmd in "wc" "/usr/bin/wc" ; do
for cmd in "wc" ; do
	test1 "${cmd}"
done


cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
