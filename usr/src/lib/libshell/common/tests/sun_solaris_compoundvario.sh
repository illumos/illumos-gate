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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors+=1 ))
}

alias err_exit='err_exit $LINENO'

typeset -C bracketstat=(
	integer bopen=0
	integer bclose=0
)

function count_brackets
{
	typeset x="$1"
	typeset c

	integer i
	(( bracketstat.bopen=0 , bracketstat.bclose=0 ))

	for (( i=0 ; i < ${#x} ; i++ )) ; do
	        c="${x:i:1}"
		[[ "$c" == "(" ]] && (( bracketstat.bopen++ ))
		[[ "$c" == ")" ]] && (( bracketstat.bclose++ ))
	done
	
	(( bracketstat.bopen != bracketstat.bclose )) && return 1
	
	return 0
}

integer Errors=0

typeset s

# Test 1:
# Check whether "read -C" leaves the file pointer at the next line
# (and does not read beyond that point).
# Data layout is:
# -- snip --
# <compound var>
# hello
# -- snip --
# (additionally we test some extra stuff like bracket count)
s=${
	typeset -C x=(
		a=1 b=2
		typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
		typeset -A myarray2=( [a]=1 [b]=2 ["c d"]=3 [e]=4 ["f"]=5 [g]=6 [h]=7 [i]=8 [j]=9 [k]=10 )
		typeset -A myarray3=(
			[a]=(
				float m1=0.5
				float m2=0.6
				foo="hello"
			)
			[b]=(
				foo="bar"
			)
			["c d"]=(
				integer at=90
			)
			[e]=(
				typeset -C nested_cpv=(
					typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
					typeset str=$'a \'string'
				)
			)
			[f]=(
				typeset g="f"
			)
		)
	)

	{
		printf "%B\n" x
		print "hello"
	} | {
		read -C y
		read s
	}
	print "x${s}x"
} || err_exit "test returned exit code $?"

[[ "${s}" == "xhellox" ]] || err_exit "Expected 'xhellox', got ${s}"
count_brackets "$y" || err_exit "y: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"

# cleanup
unset x y || err_exit "unset failed"
[[ "$x" == "" ]] || err_exit "cleanup failed for x"
[[ "$y" == "" ]] || err_exit "cleanup failed for y"


# Test 2:
# Same as test 1 except one more compound var following the "hello"
# line.
# Data layout is:
# -- snip --
# <compound var>
# hello
# <compound var>
# -- snip --
s=${
	typeset -C x=(
		a=1 b=2
		typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
		typeset -A myarray2=( [a]=1 [b]=2 ["c d"]=3 [e]=4 ["f"]=5 [g]=6 [h]=7 [i]=8 [j]=9 [k]=10 )
		typeset -A myarray3=(
			[a]=(
				float m1=0.5
				float m2=0.6
				foo="hello"
			)
			[b]=(
				foo="bar"
			)
			["c d"]=(
				integer at=90
			)
			[e]=(
				typeset -C nested_cpv=(
					typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
					typeset str=$'a \'string'
				)
			)
			[f]=(
				typeset g="f"
			)
		)
	)

	{
		printf "%B\n" x
		print "hello"
		printf "%B\n" x
	} | {
		read -C y1
		read s
		read -C y2
	}
	
	print "x${s}x"
} || err_exit "test returned exit code $?"

[[ "${s}" == "xhellox" ]] || err_exit "Expected 'xhellox', got ${s}."
[[ "$y1" != "" ]] || err_exit "y1 is empty"
[[ "$y2" != "" ]] || err_exit "y2 is empty"
count_brackets "$y1" || err_exit "y1: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$y2" || err_exit "y2: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
[[ "$y1" == "$y2" ]] || err_exit "Expected $(printf "%q\n" "${y1}") == $(printf "%q\n" "${y2}")."
[[ "$x"  == "$y1" ]] || err_exit "Expected $(printf "%q\n" "${x}") == $(printf "%q\n" "${y}")."

# cleanup
unset x y1 y2 || err_exit "unset failed"
[[ "$x" == "" ]]  || err_exit "cleanup failed for x"
[[ "$y1" == "" ]] || err_exit "cleanup failed for y1"
[[ "$y2" == "" ]] || err_exit "cleanup failed for y2"


# Test 3: Test compound variable copy operator vs. "read -C"
typeset -C x=(
	a=1 b=2
	typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
	typeset -A myarray2=( [a]=1 [b]=2 ["c d"]=3 [e]=4 ["f"]=5 [g]=6 [h]=7 [i]=8 [j]=9 [k]=10 )
	typeset -A myarray3=(
		[a]=(
			float m1=0.5
			float m2=0.6
			foo="hello"
		)
		[b]=(
			foo="bar"
		)
		["c d"]=(
			integer at=90
		)
		[e]=(
			typeset -C nested_cpv=(
				typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
				typeset str=$'a \'string'
			)
		)
		[f]=(
			typeset g="f"
		)
	)
)

typeset -C x_copy=x || err_exit "x_copy copy failed"
[[ "${x_copy}" != "" ]] || err_exit "x_copy should not be empty"
count_brackets "${x_copy}" || err_exit "x_copy: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"

typeset -C nested_cpv_copy

nested_cpv_copy=x.myarray3[e].nested_cpv || err_exit "x.myarray3[e].nested_cpv copy failed"

# unset branch "x.myarray3[e].nested_cpv" of the variable tree "x" ...
unset x.myarray3[e].nested_cpv || err_exit "unset x.myarray3[e].nested_cpv failed"
[[ "${x.myarray3[e].nested_cpv}" == "" ]] || err_exit "x.myarray3[e].nested_cpv still has a value"

# ... and restore it from the saved copy
printf "%B\n" nested_cpv_copy | read -C x.myarray3[e].nested_cpv || err_exit "read failed"

# compare copy of the original tree and the modified one
[[ "${x}" == "${x_copy}" ]] || err_exit "x != x_copy"
count_brackets "${x}" || err_exit "x: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"

# cleanup
unset x x_copy nested_cpv_copy || err_exit "unset failed"


# Test 4: Test "read -C" failure for missing bracket at the end
typeset s
s=$($SHELL -c 'typeset -C myvar ; print "( unfinished=1" | read -C myvar 2>/dev/null || print "error $?"') || err_exit "shell failed"
[[ "$s" == "error 3" ]] || err_exit "compound_read: expected error 3, got ${s}"


# Test 5: Test "read -C" failure for missing bracket at the beginning
typeset s
s=$($SHELL -c 'typeset -C myvar ; print "  unfinished=1 )" | read -C myvar 2>/dev/null || print "error $?"') || err_exit "shell failed"
[[ "$s" == "error 3" ]] || err_exit "compound_read: expected error 3, got ${s}"

# tests done
exit $((Errors))
