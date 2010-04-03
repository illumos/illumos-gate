########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2010 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                  Common Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#            http://www.opensource.org/licenses/cpl1.0.txt             #
#         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
function err_exit2
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors+=1 ))
}

function testfunc
{
	integer line_number=$1
	typeset cmd="$2"
	typeset expected_output="$3"
	typeset output

	output="$($SHELL -c "${cmd}" 2>&1 )"

	[[ "${output}" != "${expected_output}" ]] && err_exit2 ${line_number} "${output} != ${expected_output}"
}
alias testfunc='testfunc $LINENO'
alias err_exit='err_exit2 $LINENO'

Command=${0##*/}
integer Errors=0

# string
testfunc '(function l { typeset -S x ;     x+="#" ; $1 && print "$x" ; } ; l false ; l false   ; l true)'  "###"
testfunc 'function  l { typeset -S x=">" ; x+="#" ; $1 && print "$x" ; } ; l false ; l false   ; l true'   ">###"
testfunc 'function  l { typeset -S x=">" ; x+="#" ; $1 && print "$x" ; } ; l false ; (l false) ; l true'   ">##"
testfunc 'function  l { typeset -S x=">" ; x+="#" ; $1 && print "$x" ; } ; l false; ( ulimit -c 0 ; l false) ; l true' ">##"

# integer
testfunc '(function l { typeset -S -i x ;  x+=1 ;   $1 && print "$x" ; } ; l false ; l false   ; l true )' "3"
testfunc '(function l { typeset -S -i x ;  x+=1 ;   $1 && print "$x" ; } ; l false ; (l false) ; l true )' "2"

# float
testfunc '(function l { float -S x=0.5 ;  (( x+=.5 )) ;   $1 && print "$x" ; } ; l false ; l false   ; l true )' "2"
testfunc '(function l { float -S x=0.5 ;  (( x+=.5 )) ;   $1 && print "$x" ; } ; l false ; (l false) ; l true )' "1.5"

# compound variable
[[ "${
	function l
	{
		typeset -S s=( a=0 b=0 )

		(( s.a++, s.b++ ))

		$1 && printf 'a=%d, b=%d\n' s.a s.b
	}
	l false ; l false ; l true
}" != "a=3, b=3" ]] && err_exit "static compound var failed"


# array variable
expected="helloan elementan elementan element"
got=$(
	function ar
	{
		typeset -a -S s=( "hello" )

		s+=( "an element" )

		$1 && { printf '%s' "${s[@]}" ; printf '\n' ; }
	}
	ar false ; ar false ; ar true
)
[[ $got != $expected ]] && err_exit "static array var failed -- expected '$expected', got '$got'"


# Test visibilty of "global" vs. "static" variables. if we have a "static" variable in a
# function and "unset" it we should see a global variable with the same
# name, right ?
integer hx=5
function test_hx_scope
{
	integer -S hx=9
	$2 && unset hx
	$1 && printf "hx=%d\n" hx
}
test_hx_scope false false
test_hx_scope false false
# first test the "unset" call in a $(...) subshell...
[[ "$( test_hx_scope true true  )" != "hx=5" ]] && err_exit "can't see global variable hx after unsetting static variable hx"
# ... end then test whether the value has changed.
[[ "${ test_hx_scope true false }" != "hx=9" ]] && err_exit "hx variable somehow changed"

exit $((Errors))

