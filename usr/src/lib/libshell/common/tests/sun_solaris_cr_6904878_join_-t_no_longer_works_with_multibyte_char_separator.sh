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
# This test checks whether the AST "join" utility works with
# multibyte characters as seperator.
#
# This was reported as CR #6904878 ("join -t no longer works with multibyte char separator"):
# ------------ snip ------------
# join doesn't handle multibyte separator correctly.
# 
# $ echo $LANG
# ja
# $ od -tx1 input1
# 0000000 66 31 a1 f7 66 32 0a
# 0000007
# $ od -tx1 input2                    
# 0000000 74 32 a1 f7 66 31 0a
# 0000007
# # 0xa1 0xf7 in the file is multibyte character.
# $ od -tx1 delim
# 0000000 a1 f7 0a
# 0000003
# 
# $ /usr/bin/join -j1 1 -j2 2 -o 1.1 -t `cat delim` input1 input2
# $ 
# 
# It should output "f1".
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
tmpdir="$(mktemp -t -d "test_sun_solaris_cr_6904878_join_-t_no_longer_works_with_multibyte_char_separator.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }


# run tests


function test1
{
	typeset join_cmd="$1"
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
			typeset name="ascii_simple"
			typeset locale="C"
			typeset input1_format="fish 81 91\n"
			typeset input2_format="fish B A\n"
			typeset -a join_args_format=( "input1" "input2" )
			typeset output_format="fish 81 91 B A"
		)
		(
			typeset name="ja_JP.eucJP_multibyte_delimiter"
			typeset locale="ja_JP.eucJP"
			typeset input1_format="\x66\x31\xa1\xf7\x66\x32\x0a"
			typeset input2_format="\x74\x32\xa1\xf7\x66\x31\x0a"
			typeset -a join_args_format=( "-j1" "1" "-j2" "2" "-o" "1.1" "-t" "\xa1\xf7" "input1" "input2" )
			typeset output_format="f1"
		)
	)

	for testid in "${!testcases[@]}" ; do
        	nameref tc=testcases[${testid}]
		testname="${join_cmd}/${tc.name}"

		if [[ "${tc.locale}" == "<unicode>" ]] ; then
			if [[ "$LC_ALL" != *.UTF-8 ]] ; then
				export LC_ALL='en_US.UTF-8'
			fi
		else
			export LC_ALL="${tc.locale}"
		fi
		
		# build "join_args" array with multibyte characters in the current locale
		typeset -a join_args
		integer arg_index
		for arg_index in "${!tc.join_args_format[@]}" ; do
			join_args+=( "$( printf -- "${tc.join_args_format[arg_index]}" )" )
		done
		
		typeset output_format="$( printf -- "${tc.output_format}" )"
		
		#printf "args=|%q|\n" "${join_args[@]}"
		
		printf "${tc.input1_format}" >"input1"
		printf "${tc.input2_format}" >"input2"

		out="$(${SHELL} -c "${join_cmd} \"\$@\"" dummy "${join_args[@]}" 2>&1)" || err_exit "${testname}: Command returned exit code $?"
		[[ "${out}" == ${output_format} ]] || err_exit "${testname}: Expected match for $(printf "%q\n" "${output_format}"), got $(printf "%q\n" "${out}")"

		rm "input1" "input2"
		
		# cleanup and restore locale settings
		unset join_args arg_index
		[[ -v saved_locale.LC_ALL	]] && LC_ALL="${saved_locale.LC_ALL}" || unset LC_ALL
		[[ -v saved_locale.LC_CTYPE	]] && LC_CTYPE="${saved_locale.LC_CTYPE}" || unset LC_CTYPE
		[[ -v saved_locale.LANG		]] && LANG="${saved_locale.LANG}" || unset LANG
	done

	return 0
}


function test2
{
	typeset joincmd=$1
	typeset testname="${joincmd}"
	typeset out

	# create files
	printf "\x66\x31\xa1\xf7\x66\x32\x0a" >"input1"
	printf "\x74\x32\xa1\xf7\x66\x31\x0a" >"input2"
	printf "\xa1\xf7\x0a" >"delim"

	# run test
	out=$( LC_ALL=ja_JP.eucJP ${SHELL} -o pipefail -o errexit -c '$1 -j1 1 -j2 2 -o 1.1 -t $(cat delim) input1 input2' dummy "${joincmd}" 2>&1 ) || err_exit "${testname}: Test failed with exit code $?"
	[[ "${out}" == 'f1' ]] || err_exit "${testname}: Expected 'f1', got $(printf "%q\n" "${out}")"

	# cleanup
	rm "input1" "input2" "delim"

	return 0
}

#for cmd in "/usr/bin/join" "join" ; do
for cmd in "join" ; do
	test1 "${cmd}"
	test2 "${cmd}"
done



cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
