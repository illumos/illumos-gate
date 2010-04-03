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

function err_exit2
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
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

set -o nounset
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
[[ "$(
	function ar
	{
		typeset -a -S s=( "hello" )
	
		s+=( "an element" )
	
		$1 && { printf '%s' "${s[@]}" ; printf '\n' ; }
	}
	ar false ; ar false ; ar true
)" != "helloan elementan elementan element" ]] && err_exit "static array var failed"


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


# tests done
exit $((Errors))
