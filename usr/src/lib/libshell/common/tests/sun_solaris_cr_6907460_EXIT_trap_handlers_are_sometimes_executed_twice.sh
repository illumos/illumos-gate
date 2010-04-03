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
# This test checks whether the EXIT trap is called correctly in subshells
#
# This was reported as CR #6907460 ("EXIT trap handlers are sometimes executed twice"):
# ------------ snip ------------
# During SST testing of snv_128(RE) we found out that ksh93 executes EXIT
# trap handlers twice under some circumstances.
# 
# Here is a test script:
# ---
# #!/bin/ksh93 -x
# 
# function A
# {
#         set -x
#         trap "print TRAP A >>log" EXIT
#         print >&2
# }
# 
# function B
# {
#         set -x
#         trap "print TRAP B >>log" EXIT
#         A
# }
# 
# rm -f log
# x=$(B)
# ---
# 
# It produces the following output on snv_128:
# ---
# + rm -f log
# + B
# + trap 'print TRAP B >>log' EXIT
# + A
# + trap 'print TRAP A >>log' EXIT
# + print
# + + print TRAP A
# 1>& 2
# + 1>> log
# + print TRAP B
# 
# + 1>> log
# + print TRAP A
# + 1>> log
# + print TRAP B
# + 1>> log
# + x=''
# ---
# 
# The log file then contains:
# TRAP A
# TRAP B
# TRAP A
# TRAP B
# 
# However, the expected log would be:
# TRAP A
# TRAP B
# 
# When the "x=$(B)" line is changed to "B", the log is correct:
# TRAP A
# TRAP B
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
tmpdir="$(mktemp -t -d "test_sun_solaris_cr_6907460_EXIT_trap_handlers_are_sometimes_executed_twice.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }


# run tests

# test 1: Run test with some variations
compound vari
typeset testname

for vari.shell_options in \
	"" \
	"-o xtrace" \
	"-o errexit" \
	"-o errexit -o xtrace" ; do
	for vari.xtrace1 in \
		"" \
		"set -x" ; do
		for vari.xtrace2 in \
			"" \
			"set -x" ; do
			for vari.func_A_end in \
				"" \
				"print >&2" \
				"return 0" \
				"print >&2 ; return 0" ; do
				for vari.subshell in \
					$'x=$(B)' \
					$'x=$( ( B ) )' \
					$'x=${ B ; }' \
					$'x=${ ( B ) ; }' \
					$'( x=$(B) )' \
					$'( x=$( ( B ) ) )' \
					$'( x=${ B ; } )' \
					$'( x=${ ( B ) ; } )' ; do
					testname="$( printf "test |%#B|\n" vari )"

cat >"testscript.sh" <<EOF
		function A
		{
			${vari.xtrace1}
			trap "print TRAP A >>log" EXIT
			${vari.func_A_end}
		}

		function B
		{
			${vari.xtrace2}
			trap "print TRAP B >>log" EXIT
			A
		}

		rm -f log
		${vari.subshell}
EOF
					${SHELL} ${vari.shell_options} "testscript.sh" >/dev/null 2>&1 || err_exit "${testname}: Unexpected error code $?"
					rm "testscript.sh"
					
					if [[ -f "log" ]] ; then
						out="$( < log )"
						rm "log"
					else
						err_exit "${testname}: File 'log' not found."
					fi
					[[ "${out}" == $'TRAP A\nTRAP B' ]] || err_exit "${testname}: Expected \$'TRAP A\nTRAP B', got $(printf "%q\n" "${out}")"
				done
			done
		done
	done
done



# test 2: This is the unmodified test from the bugster bug report
(
cat <<EOF
	function A
	{
       		set -x
        	trap "print TRAP A >>log" EXIT
        	print >&2
	}

	function B
	{
		set -x
		trap "print TRAP B >>log" EXIT
		A
	}

	rm -f log
	x=\$(B)
EOF
) | ${SHELL} >/dev/null 2>&1 || err_exit "Unexpected error code $?"

if [[ -f "log" ]] ; then
	out="$( < log )"
	rm "log"
else
	err_exit "File 'log' not found."
fi
[[ "${out}" == $'TRAP A\nTRAP B' ]] || err_exit "Expected \$'TRAP A\nTRAP B', got $(printf "%q\n" "${out}")"


cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
