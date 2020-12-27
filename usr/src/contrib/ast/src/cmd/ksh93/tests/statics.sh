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
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

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



typeset -T test_t=(
	typeset name
	typeset cmd
	typeset expected_output
)

function testfunc
{
	integer line_number=$1
	typeset cmd="$2"
	typeset expected_output="$3"
	typeset output
	
	output="$($SHELL -c "${cmd}" 2>&1 )"
	
	[[ "${output}" == "${expected_output}" ]] || err_exit ${line_number} "${output} != ${expected_output}"
}

# test1: basic tests
function test1
{
	# string
	testfunc ${LINENO} '(function l { typeset -S x ;     x+="#" ; $1 && print "$x" ; } ; l false ; l false   ; l true)'  "###"
	testfunc ${LINENO} 'function  l { typeset -S x=">" ; x+="#" ; $1 && print "$x" ; } ; l false ; l false   ; l true'   ">###"
	testfunc ${LINENO} 'function  l { typeset -S x=">" ; x+="#" ; $1 && print "$x" ; } ; l false ; (l false) ; l true'   ">##"
	testfunc ${LINENO} 'function  l { typeset -S x=">" ; x+="#" ; $1 && print "$x" ; } ; l false; ( ulimit -c 0 ; l false) ; l true' ">##"
	
	# integer
	# (normal)
	testfunc ${LINENO} '(function l { integer -S x ;        x+=1 ;   $1 && print "$x" ; } ; l false ; l false   ; l true )' "3"
	testfunc ${LINENO} '(function l { integer -S x ;        x+=1 ;   $1 && print "$x" ; } ; l false ; (l false) ; l true )' "2"
	# (int)
	testfunc ${LINENO} '(function l { typeset -S -i x ;     x+=1 ;   $1 && print "$x" ; } ; l false ; l false   ; l true )' "3"
	testfunc ${LINENO} '(function l { typeset -S -i x ;     x+=1 ;   $1 && print "$x" ; } ; l false ; (l false) ; l true )' "2"
	# (short)
	testfunc ${LINENO} '(function l { typeset -S -s -i x ;  x+=1 ;   $1 && print "$x" ; } ; l false ; l false   ; l true )' "3"
	testfunc ${LINENO} '(function l { typeset -S -s -i x ;  x+=1 ;   $1 && print "$x" ; } ; l false ; (l false) ; l true )' "2"
	
	# float
	testfunc ${LINENO} '(function l { float -S x=0.5 ;  (( x+=.5 )) ;   $1 && print "$x" ; } ; l false ; l false   ; l true )' "2"
	testfunc ${LINENO} '(function l { float -S x=0.5 ;  (( x+=.5 )) ;   $1 && print "$x" ; } ; l false ; (l false) ; l true )' "1.5"

	return 0
}

# test2: test the more complex datatypes
function test2
{
        compound out=( typeset stdout stderr ; integer res )
	integer i
	
	test_t -r -a tests=(
		(
			name='compound'
			cmd=$'
				function l
				{
					compound -S s=(
						integer a=1
						integer b=2
					)
				
					(( s.a++, s.b++ ))
				
					$1 && printf "a=%d, b=%d\n" s.a s.b
				}
				(l false ; l false ; l true ; printf ";")
				(l false ; l false ; l true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)
		(
			name='compound_nameref'
			cmd=$'
				function l_n
				{
					nameref sn=$2
					(( sn.a++, sn.b++ ))
				
					$1 && printf "a=%d, b=%d\n" sn.a sn.b
				}
				function l
				{
					compound -S s=( a=1 b=2 )
					l_n $1 s
				}
				(l false ; l false ; l true ; printf ";")
				(l false ; l false ; l true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='type'
			cmd=$'
				typeset -T ab_t=(
					integer a=1
					integer b=2
					
					function increment
					{
						(( _.a++, _.b++ ))
					}
				)
				function l
				{
					ab_t -S s
				
					s.increment
				
					$1 && printf "a=%d, b=%d\n" s.a s.b
				}
				(l false ; l false ; l true ; printf ";")
				(l false ; l false ; l true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='type_nameref'
			cmd=$'
				typeset -T ab_t=(
					integer a=1
					integer b=2
					
					function increment
					{
						(( _.a++, _.b++ ))
					}
				)
				function l_n
				{
					nameref sn=$2

					sn.increment
				
					$1 && printf "a=%d, b=%d\n" sn.a sn.b
				}
				function l
				{
					ab_t -S s
					l_n $1 s		
				}
				(l false ; l false ; l true ; printf ";")
				(l false ; l false ; l true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='indexed_string_array_appendelement'
			cmd=$'
				function ar
				{
					typeset -a -S s=( "hello" )
				
					s+=( "an element" )
				
					$1 && { printf "%s" "${s[@]}" ; printf "\n" ; }
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'helloan elementan elementan element\n;helloan elementan elementan element\n;'
		)

		(
			name='indexed_string_array_nameref_appendelement'
			cmd=$'
				function ar_n
				{
					nameref sn=$2
					sn+=( "an element" )
				
					$1 && { printf "%s" "${sn[@]}" ; printf "\n" ; }
				}
				function ar
				{
					typeset -a -S s=( "hello" )
					ar_n $1 s
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'helloan elementan elementan element\n;helloan elementan elementan element\n;'
		)

		(
			name='associative_string_array_appendelement'
			cmd=$'
				function ar
				{
					typeset -A -S s=( [0]="hello" )
				
					s[$(( ${#s[@]} + 1))]="an element"
				
					$1 && { printf "%s" "${s[@]}" ; printf "\n" ; }
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'helloan elementan elementan element\n;helloan elementan elementan element\n;'
		)

		(
			name='associative_string_array_nameref_appendelement'
			cmd=$'
				function ar_n
				{
					nameref sn=$2
					
					sn[$(( ${#sn[@]} + 1))]="an element"
				
					$1 && { printf "%s" "${sn[@]}" ; printf "\n" ; }
				}
				function ar
				{
					typeset -A -S s=( [0]="hello" )
					ar_n $1 s		
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'helloan elementan elementan element\n;helloan elementan elementan element\n;'
		)

		(
			name='indexed_compound_array_editelement'
			cmd=$'
				function ar
				{
					compound -S -a s=( 
						[5]=(
							integer a=1
							integer b=2
						)
					)

					(( s[5].a++, s[5].b++ ))				
					$1 && printf "a=%d, b=%d\n" s[5].a s[5].b
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='indexed_compound_array_nameref_editelement'
			cmd=$'
				function ar_n
				{
					nameref sn=$2

					(( sn.a++, sn.b++ ))				
					$1 && printf "a=%d, b=%d\n" sn.a sn.b
				}
				function ar
				{
					compound -S -a s=( 
						[5]=(
							integer a=1
							integer b=2
						)
					)

					ar_n $1 s[5]
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='2d_indexed_compound_array_editelement'
			cmd=$'
				function ar
				{
					compound -S -a s=( 
						[8][5]=(
							integer a=1
							integer b=2
						)
					)

					(( s[8][5].a++, s[8][5].b++ ))				
					$1 && printf "a=%d, b=%d\n" s[8][5].a s[8][5].b
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='2d_indexed_compound_array_nameref_editelement'
			cmd=$'
				function ar_n
				{
					nameref sn=$2

					(( sn.a++, sn.b++ ))				
					$1 && printf "a=%d, b=%d\n" sn.a sn.b
				}
				function ar
				{
					compound -S -a s=( 
						[8][5]=(
							integer a=1
							integer b=2
						)
					)

					ar_n $1 s[8][5]
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)
		(
			name='4d_indexed_compound_array_editelement'
			cmd=$'
				function ar
				{
					compound -S -a s=( 
						[8][5][0][9]=(
							integer a=1
							integer b=2
						)
					)

					(( s[8][5][0][9].a++, s[8][5][0][9].b++ ))				
					$1 && printf "a=%d, b=%d\n" s[8][5][0][9].a s[8][5][0][9].b
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='4d_indexed_compound_array_nameref_editelement'
			cmd=$'
				function ar_n
				{
					nameref sn=$2

					(( sn.a++, sn.b++ ))				
					$1 && printf "a=%d, b=%d\n" sn.a sn.b
				}
				function ar
				{
					compound -S -a s=( 
						[8][5][0][9]=(
							integer a=1
							integer b=2
						)
					)

					ar_n $1 s[8][5][0][9]
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='associative_compound_array_editelement'
			cmd=$'
				function ar
				{
					compound -S -A s=( 
						[5]=(
							integer a=1
							integer b=2
						)
					)

					(( s[5].a++, s[5].b++ ))				
					$1 && printf "a=%d, b=%d\n" s[5].a s[5].b
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

		(
			name='associative_compound_array_nameref_editelement'
			cmd=$'
				function ar_n
				{
					nameref sn=$2

					(( sn.a++, sn.b++ ))				
					$1 && printf "a=%d, b=%d\n" sn.a sn.b
				}
				function ar
				{
					compound -S -A s=( 
						[5]=(
							integer a=1
							integer b=2
						)
					)

					ar_n $1 s[5]
				}
				(ar false ; ar false ; ar true ; printf ";")
				(ar false ; ar false ; ar true ; printf ";")
			'
			expected_output=$'a=4, b=5\n;a=4, b=5\n;'
		)

			(
				name='indexed_type_array_editelement'
				cmd=$'
					typeset -T ab_t=(
						integer a=1
						integer b=2
						
						function increment
						{
							(( _.a++, _.b++ ))
						}
					)

					function ar
					{
						ab_t -S -a s
						[[ -v s[5] ]] || s[5]=( ) # how do I init an array of types ?

						s[5].increment
						$1 && printf "a=%d, b=%d\n" s[5].a s[5].b
					}
					(ar false ; ar false ; ar true ; printf ";")
					(ar false ; ar false ; ar true ; printf ";")
				'
				expected_output=$'a=4, b=5\n;a=4, b=5\n;'
			)

			(
				name='indexed_type_array_nameref_editelement'
				cmd=$'
					typeset -T ab_t=(
						integer a=1
						integer b=2
						
						function increment
						{
							(( _.a++, _.b++ ))
						}
					)

					function ar_n
					{
						nameref sn=$2

						sn.increment
						$1 && printf "a=%d, b=%d\n" sn.a sn.b
					}
					function ar
					{
						ab_t -S -a s
						[[ -v s[5] ]] || s[5]=( ) # how do I init an array of types ?

						ar_n $1 s[5]
					}
					(ar false ; ar false ; ar true ; printf ";")
					(ar false ; ar false ; ar true ; printf ";")
				'
				expected_output=$'a=4, b=5\n;a=4, b=5\n;'
			)

			(
				name='2d_indexed_type_array_editelement'
				cmd=$'
					typeset -T ab_t=(
						integer a=1
						integer b=2
						
						function increment
						{
							(( _.a++, _.b++ ))
						}
					)

					function ar
					{
						ab_t -S -a s
						[[ -v s[9][5] ]] || s[9][5]=( ) # how do I init an array of types ?

						s[9][5].increment
						$1 && printf "a=%d, b=%d\n" s[9][5].a s[9][5].b
					}
					(ar false ; ar false ; ar true ; printf ";")
					(ar false ; ar false ; ar true ; printf ";")
				'
				expected_output=$'a=4, b=5\n;a=4, b=5\n;'
			)

			(
				name='2d_indexed_type_array_nameref_editelement'
				cmd=$'
					typeset -T ab_t=(
						integer a=1
						integer b=2
						
						function increment
						{
							(( _.a++, _.b++ ))
						}
					)

					function ar_n
					{
						nameref sn=$2

						sn.increment
						$1 && printf "a=%d, b=%d\n" sn.a sn.b
					}
					function ar
					{
						ab_t -S -a s
						[[ -v s[9][5] ]] || s[9][5]=( ) # how do I init an array of types ?

						ar_n $1 s[9][5]
					}
					(ar false ; ar false ; ar true ; printf ";")
					(ar false ; ar false ; ar true ; printf ";")
				'
				expected_output=$'a=4, b=5\n;a=4, b=5\n;'
			)

			(
				name='associative_type_array_editelement'
				cmd=$'
					typeset -T ab_t=(
						integer a=1
						integer b=2
						
						function increment
						{
							(( _.a++, _.b++ ))
						}
					)

					function ar
					{
						ab_t -S -A s
						[[ -v s[5] ]] || s[5]=( ) # how do I init an array of types ?

						s[5].increment
						$1 && printf "a=%d, b=%d\n" s[5].a s[5].b
					}
					(ar false ; ar false ; ar true ; printf ";")
					(ar false ; ar false ; ar true ; printf ";")
				'
				expected_output=$'a=4, b=5\n;a=4, b=5\n;'
			)

			(
				name='associative_type_array_nameref_editelement'
				cmd=$'
					typeset -T ab_t=(
						integer a=1
						integer b=2
						
						function increment
						{
							(( _.a++, _.b++ ))
						}
					)

					function ar_n
					{
						nameref sn=$2

						sn.increment
						$1 && printf "a=%d, b=%d\n" sn.a sn.b
					}
					function ar
					{
						ab_t -S -A s
						[[ -v s[5] ]] || s[5]=( ) # how do I init an array of types ?

						ar_n $1 s[5]
					}
					(ar false ; ar false ; ar true ; printf ";")
					(ar false ; ar false ; ar true ; printf ";")
				'
				expected_output=$'a=4, b=5\n;a=4, b=5\n;'
			)

	)
	
	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		nameref currtest=tests[i]

#print -u2 -- "${currtest.cmd}"
		out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -c "${currtest.cmd}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

		(( out.res == 0 )) || err_exit "${currtest.name}: Test shell returned with exit code ${out.res}"
		[[ "${out.stdout}" == "${currtest.expected_output}" ]] || err_exit "${currtest.name}: Expected stdout == $(printf "%q\n" "${currtest.expected_output}"), got $(printf "%q\n" "${out.stdout}")"
		[[ "${out.stderr}" == '' ]] || err_exit "${currtest.name}: Expected empty stderr, got $(printf "%q\n" "${out.stderr}")"
   	done

	return 0
}

# run tests
test1
test2


# Test visibilty of "global" vs. "static" variables. if we have a "static" variable in a
# function and "unset" it we should see a global variable with the same
# name, right ?
integer hx=5
function test_hx_scope
{
	integer -S hx=9
	$2 && unset hx
	$1 && printf 'hx=%d\n' hx
}
test_hx_scope false false
test_hx_scope false false
# first test the "unset" call in a $(...) subshell...
[[ "$( test_hx_scope true true   )" == 'hx=5' ]] || err_exit "can't see global variable hx after unsetting static variable hx"
# ... end then test whether the value has changed.
[[ "${ test_hx_scope true false ;}" == 'hx=9' ]] || err_exit "hx variable somehow changed"

out=$(function fun2
{
        nameref sn=$1
        (( sn.a++, sn.b++ ))
        $2 && printf "a=%d, b=%d\n" sn.a sn.b
}
function fun1
{
        compound -S s=( a=0 b=0 )
        fun2 s $1
}
(fun1 false ; fun1 false ; fun1 true)
(fun1 false ; fun1 false ; fun1 true)
)
[[ $out == $'a=3, b=3\na=3, b=3' ]] || err_exit 'static variables in functions with initializers not working'

exit $((Errors<125?Errors:125))
