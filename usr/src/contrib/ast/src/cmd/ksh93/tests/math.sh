########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                 Eclipse Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#          http://www.eclipse.org/org/documents/epl-v10.html           #
#         (with md5 checksum b35adb5213ca9657e911e9befb180842)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
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

set -o nounset

typeset tmp

# create temporary test directory
tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT
cd $tmp || exit

function test_arithmetric_expression_accesss_array_element_through_nameref
{
        compound out=( typeset stdout stderr ; integer res )
	compound -r -a tests=(
		(
			cmd='@@TYPE@@ -a @@VAR@@ ;  @@VAR@@[1]=90 ;       function x { nameref nz=$1 ;              print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1]'		; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -a @@VAR@@=( [1]=90 ) ;             function x { nameref nz=$1 ;              print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1]'		; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -a @@VAR@@ ;  @@VAR@@[1][3]=90 ;    function x { nameref nz=$1 ;               print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1][3]'	; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -a @@VAR@@=( [1][3]=90 ) ;          function x { nameref nz=$1 ;               print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1][3]'	; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -a @@VAR@@ ;  @@VAR@@[1][3][5]=90 ; function x { nameref nz=$1 ;               print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1][3][5]'	; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -a @@VAR@@=( [1][3][5]=90 ) ;       function x { nameref nz=$1 ;               print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1][3][5]'	; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -a @@VAR@@ ;  @@VAR@@[1][3][5]=90 ; function x { nameref nz=${1}[$2][$3][$4] ; print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@ 1 3 5'	; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -A @@VAR@@ ;  @@VAR@@[1]=90 ;       function x { nameref nz=$1 ;               print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1]'		; stdoutpattern=' 90==90'
		)
		(
			cmd='@@TYPE@@ -A @@VAR@@=( [1]=90 ) ;             function x { nameref nz=$1 ;               print " $(( round(nz) ))==$(( round($nz) ))" ; } ; x @@VAR@@[1]'		; stdoutpattern=' 90==90'
		)
	)

	typeset testname
	integer i
	typeset mode
	typeset cmd

	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		# fixme: This list should include "typeset -lX" and "typeset -X" but ast-ksh.2010-03-09 fails like this:
		# 'typeset -X -a z ;  z[1][3]=90 ; function x { nameref nz=$1 ; print " $(( nz ))==$(( $nz ))" ; } ; x z[1][3]'
		# + typeset -X -a z
		# + z[1][3]=90
		# + x 'z[1][3]'
		# /home/test001/bin/ksh[1]: x: line 1: x1.68000000000000000000000000000000p: no parent
		for ty in \
			'typeset' \
			'integer' \
			'float' \
			'typeset -i' \
			'typeset -si' \
			'typeset -li' \
			'typeset -E' \
			'typeset -F' \
			'typeset -X' \
			'typeset -lE' \
			'typeset -lX' \
			'typeset -lF' ; do
			for mode in \
				'plain' \
				'in_compound' \
				'in_indexed_compound_array' \
				'in_2d_indexed_compound_array' \
				'in_4d_indexed_compound_array' \
				'in_associative_compound_array' \
				'in_compound_nameref' \
				'in_indexed_compound_array_nameref' \
				'in_2d_indexed_compound_array_nameref' \
				'in_4d_indexed_compound_array_nameref' \
				'in_associative_compound_array_nameref' \
				 ; do
				nameref tst=tests[i]
			
				cmd="${tst.cmd//@@TYPE@@/${ty}}"
				
				case "${mode}" in
					'plain')
						cmd="${cmd//@@VAR@@/z}"
						;;

					'in_compound')
						cmd="compound c ; ${cmd//@@VAR@@/c.z}"
						;;
					'in_indexed_compound_array')
						cmd="compound -a c ; ${cmd//@@VAR@@/c[11].z}"
						;;
					'in_2d_indexed_compound_array')
						cmd="compound -a c ; ${cmd//@@VAR@@/c[17][19].z}"
						;;
					'in_4d_indexed_compound_array')
						cmd="compound -a c ; ${cmd//@@VAR@@/c[17][19][23][27].z}"
						;;
					'in_associative_compound_array')
						cmd="compound -A c ; ${cmd//@@VAR@@/c[info].z}"
						;;

					'in_compound_nameref')
						cmd="compound c ; nameref ncr=c.z ; ${cmd//@@VAR@@/ncr}"
						;;
					'in_indexed_compound_array_nameref')
						cmd="compound -a c ; nameref ncr=c[11].z ; ${cmd//@@VAR@@/ncr}"
						;;
					'in_2d_indexed_compound_array_nameref')
						cmd="compound -a c ; nameref ncr=c[17][19].z ; ${cmd//@@VAR@@/ncr}"
						;;
					'in_4d_indexed_compound_array_nameref')
						cmd="compound -a c ; nameref ncr=c[17][19][23][27].z ; ${cmd//@@VAR@@/ncr}"
						;;
					'in_associative_compound_array_nameref')
						cmd="compound -A c ; nameref ncr=c[info].z ; ${cmd//@@VAR@@/ncr}"
						;;
					*)
						err_exit "Unexpected mode ${mode}"
						;;
				esac
								
				testname="${0}/${cmd}"
#set -x
				out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -o errexit -c "${cmd}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"
#set +x

			        [[ "${out.stdout}" == ${tst.stdoutpattern}      ]] || err_exit "${testname}: Expected stdout to match $(printf '%q\n' "${tst.stdoutpattern}"), got $(printf '%q\n' "${out.stdout}")"
       				[[ "${out.stderr}" == ''			]] || err_exit "${testname}: Expected empty stderr, got $(printf '%q\n' "${out.stderr}")"
				(( out.res == 0 )) || err_exit "${testname}: Unexpected exit code ${out.res}"
			done
		done
	done
	
	return 0
}

function test_has_iszero
{
	typeset str
	integer i
	
	typeset -r -a tests=(
		'(( iszero(0)   )) && print "OK"'
		'(( iszero(0.)  )) && print "OK"'
		'(( iszero(-0)  )) && print "OK"'
		'(( iszero(-0.) )) && print "OK"'
		'float n=0.  ; (( iszero(n) )) && print "OK"'
		'float n=+0. ; (( iszero(n) )) && print "OK"'
		'float n=-0. ; (( iszero(n) )) && print "OK"'
		'float n=1.  ; (( iszero(n) )) || print "OK"'
		'float n=1.  ; (( iszero(n-1.) )) && print "OK"'
		'float n=-1. ; (( iszero(n+1.) )) && print "OK"'
	)
	
	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		str="$( ${SHELL} -o errexit -c "${tests[i]}" 2>&1 )" || err_exit "test $i: returned non-zero exit code $?"
		[[ "${str}" == 'OK' ]] || err_exit "test $i: expected 'OK', got '${str}'"
	done

	return 0
}

# run tests
test_arithmetric_expression_accesss_array_element_through_nameref
test_has_iszero

exit $((Errors<125?Errors:125))
