########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2012 AT&T Intellectual Property          #
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
########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2012 AT&T Intellectual Property          #
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
#              Roland Mainz <roland.mainz@nrubsig.org>                 #
#                                                                      #
########################################################################

# test setup
function err_exit
{
	print -u2 -n '\t'
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors++ ))
}
alias err_exit='err_exit $LINENO'

# "nounset" disabled for now
#set -o nounset
Command=${0##*/}
integer Errors=0 HAVE_signbit=0

if	typeset -f .sh.math.signbit >/dev/null && (( signbit(-NaN) ))
then	HAVE_signbit=1
else	print -u2 "$0: warning: -lm does not support signbit(-NaN)"
fi

compound bracketstat=(
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
		[[ "$c" == '(' ]] && (( bracketstat.bopen++ ))
		[[ "$c" == ')' ]] && (( bracketstat.bclose++ ))
	done
	
	(( bracketstat.bopen != bracketstat.bclose )) && return 1
	
	return 0
}

# compound variable "cat" nr.1, using $ print "%B\n" ... #
function cpvcat1
{
	set -o errexit
	compound tmp
	
	while read -C tmp ; do printf '%B\n' tmp ; done
	return 0
}

# compound variable "cat" nr.2, using $ print "%#B\n" ... #
function cpvcat2
{
	set -o errexit
	compound tmp
	
	while read -C tmp ; do printf '%#B\n' tmp ; done
	return 0
}

# compound variable "cat" nr.3, using $ print -C ... #
function cpvcat3
{
	set -o errexit
	compound tmp
	
	while read -C tmp ; do print -C tmp ; done
	return 0
}

# compound variable "cat" nr.4, using $ print -v ... #
function cpvcat4
{
	set -o errexit
	compound tmp
	
	while read -C tmp ; do print -v tmp ; done
	return 0
}

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
	compound x=(
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
				compound nested_cpv=(
					typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
					typeset str=$'a \'string'
				)
			)
			[f]=(
				typeset g="f"
			)
			[a_nan]=(
				float my_nan=-nan
			)
			[a_hexfloat]=(
			       typeset -X my_hexfloat=1.1
			)
		)
	)

	{
		printf "%B\n" x
		print "hello"
	} | cpvcat1 | cpvcat2 | cpvcat3 | cpvcat4 | {
		read -C y
		read s
	}
	print "x${s}x"
} || err_exit "test returned exit code $?"

[[ "${s}" == "xhellox" ]] || err_exit "Expected 'xhellox', got ${s}"
count_brackets "$y" || err_exit "y: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -v y)" || err_exit "y: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -C y)" || err_exit "y: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"

# cleanup
unset x y || err_exit "unset failed"
[[ "$x" == '' ]] || err_exit "cleanup failed for x"
[[ "$y" == '' ]] || err_exit "cleanup failed for y"


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
	compound x=(
		a=1 b=2
		typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
		typeset -A myarray2=( [a]=1 [b]=2 ["c d"]=3 [e]=4 ["f"]=5 [g]=6 [h]=7 [i]=8 [j]=9 [k]=10 )
		compound -A myarray3=(
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
				compound nested_cpv=(
					typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
					typeset str=$'a \'string'
				)
			)
			[f]=(
				typeset g="f"
			)
			[a_nan]=(
				float my_nan=-nan
			)
			[a_hexfloat]=(
			       typeset -X my_hexfloat=1.1
			)
		)
	)

	{
		printf "%B\n" x
		print "hello"
		printf "%B\n" x
	} | cpvcat1 | cpvcat2 | cpvcat3 | cpvcat4 | {
		read -C y1
		read s
		read -C y2
	}
	
	print "x${s}x"
} || err_exit "test returned exit code $?"

[[ "${s}" == "xhellox" ]] || err_exit "Expected 'xhellox', got ${s}."
[[ "${y1.myarray3[b].foo}" == "bar" ]] || err_exit "y1.myarray3[b].foo != bar"
[[ "${y2.myarray3[b].foo}" == "bar" ]] || err_exit "y2.myarray3[b].foo != bar"
[[ "$y1" != "" ]] || err_exit "y1 is empty"
[[ "$y2" != "" ]] || err_exit "y2 is empty"
(( ${#y1.myarray3[e].nested_cpv.myarray[@]} == 10 )) || err_exit "Expected 10 elements in y1.myarray3[e].nested_cpv, got ${#y1.myarray3[e].nested_cpv[@]}"
(( ${#y2.myarray3[e].nested_cpv.myarray[@]} == 10 )) || err_exit "Expected 10 elements in y2.myarray3[e].nested_cpv, got ${#y2.myarray3[e].nested_cpv[@]}"
(( isnan(y1.myarray3[a_nan].my_nan) ))   || err_exit "y1.myarray3[a_nan].my_nan not a NaN"
(( isnan(y2.myarray3[a_nan].my_nan) ))   || err_exit "y2.myarray3[a_nan].my_nan not a NaN"
if	(( HAVE_signbit ))
then	(( signbit(y1.myarray3[a_nan].my_nan) )) || err_exit "y1.myarray3[a_nan].my_nan not negative"
	(( signbit(y2.myarray3[a_nan].my_nan) )) || err_exit "y2.myarray3[a_nan].my_nan not negative"
fi
count_brackets "$y1" || err_exit "y1: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -v y1)" || err_exit "y1: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -C y1)" || err_exit "y1: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$y2" || err_exit "y2: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -v y2)" || err_exit "y2: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -C y2)" || err_exit "y2: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
[[ "$y1" == "$y2" ]] || err_exit "Expected $(printf "%q\n" "${y1}") == $(printf "%q\n" "${y2}")."
[[ "$x"  == "$y1" ]] || err_exit "Expected $(printf "%q\n" "${x}") == $(printf "%q\n" "${y1}")."

# cleanup
unset x y1 y2 || err_exit "unset failed"
[[ "$x" == '' ]]  || err_exit "cleanup failed for x"
[[ "$y1" == '' ]] || err_exit "cleanup failed for y1"
[[ "$y2" == '' ]] || err_exit "cleanup failed for y2"


# Test 3: Test compound variable copy operator vs. "read -C"
compound x=(
	a=1 b=2
	typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
	typeset -A myarray2=( [a]=1 [b]=2 ["c d"]=3 [e]=4 ["f"]=5 [g]=6 [h]=7 [i]=8 [j]=9 [k]=10 )
	compound -A myarray3=(
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
			compound nested_cpv=(
				typeset -a myarray=( 1 2 3 4 5 6 7 8 9 10 )
				typeset str=$'a \'string'
			)
		)
		[f]=(
			typeset g="f"
		)
		[a_nan]=(
			float my_nan=-nan
		)
		[a_hexfloat]=(
		       typeset -X my_hexfloat=1.1
		)
	)
)

compound x_copy=x || err_exit "x_copy copy failed"
[[ "${x_copy}" != "" ]] || err_exit "x_copy should not be empty"
count_brackets "${x_copy}" || err_exit "x_copy: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -v x_copy)" || err_exit "x_copy: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -C x_copy)" || err_exit "x_copy: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"

compound nested_cpv_copy

nested_cpv_copy=x.myarray3[e].nested_cpv || err_exit "x.myarray3[e].nested_cpv copy failed"
(( ${#nested_cpv_copy.myarray[@]} == 10 )) || err_exit "Expected 10 elements in nested_cpv_copy.myarray, got ${#nested_cpv_copy.myarray[@]}"

# unset branch "x.myarray3[e].nested_cpv" of the variable tree "x" ...
unset x.myarray3[e].nested_cpv || err_exit "unset x.myarray3[e].nested_cpv failed"
[[ "${x.myarray3[e].nested_cpv}" == "" ]] || err_exit "x.myarray3[e].nested_cpv still has a value"

# ... and restore it from the saved copy
printf "%B\n" nested_cpv_copy | cpvcat1 | cpvcat2 | cpvcat3 | cpvcat4 | read -C x.myarray3[e].nested_cpv || err_exit "read failed"

# compare copy of the original tree and the modified one
[[ "${x}" == "${x_copy}" ]] || err_exit "x != x_copy"
count_brackets "${x}" || err_exit "x: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -v x)" || err_exit "x: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
count_brackets "$(print -C x)" || err_exit "x: bracket open ${bracketstat.bopen} != bracket close ${bracketstat.bclose}"
(( ${#x.myarray3[e].nested_cpv.myarray[@]} == 10 )) || err_exit "Expected 10 elements in x.myarray3[e].nested_cpv, got ${#x.myarray3[e].nested_cpv[@]}"
(( isnan(x.myarray3[a_nan].my_nan) ))   || err_exit "x.myarray3[a_nan].my_nan not a NaN"
if	(( HAVE_signbit ))
then	(( signbit(x.myarray3[a_nan].my_nan) )) || err_exit "x.myarray3[a_nan].my_nan not negative"
fi

# cleanup
unset x x_copy nested_cpv_copy || err_exit "unset failed"


# Test 4: Test "read -C" failure for missing bracket at the end
typeset s
s=$($SHELL -c 'compound myvar ; print "( unfinished=1" | read -C myvar 2>'/dev/null' || print "error $?"') || err_exit 'shell failed'
[[ "$s" == 'error 3' ]] || err_exit "compound_read: expected error 3, got ${s}"


# Test 5: Test "read -C" failure for missing bracket at the beginning
typeset s
s=$($SHELL -c 'compound myvar ; print "  unfinished=1 )" | read -C myvar 2>'/dev/null' || print "error $?"') || err_exit 'shell failed'
[[ "$s" == 'error 3' ]] || err_exit "compound_read: expected error 3, got ${s}"


# test6: Derived from the test2 for CR #6944386
# ("compound v=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -C v prints trash")
# which caused compound variables to be corrupted like this:
# -- snip --
# ksh93 -c 'compound v=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -v v'
# (
#        typeset -A -l -i ar=(
#                [aa]=$'\004'
#                [bb]=$'\t'
#        )
# )
# -- snip --

function test6
{
        compound out=( typeset stdout stderr ; integer res )
	compound val
	integer testid
	
	compound -r -a tests=(
		# subtests1:
		( cmd='compound v=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -C v' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='ar' )
		( cmd='compound v=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -C v' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)' 			arrefname='ar' )
		( cmd='compound v=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -C v' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='ar' )
		( cmd='compound v=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -v v' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)' 			arrefname='ar' )
		( cmd='compound v=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -v v' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)' 			arrefname='ar' )
		( cmd='compound v=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; print -v v' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)' 	arrefname='ar' )

		# subtests2: Same as subtests1 but variable "v" is inside "vx"
		( cmd='compound vx=( compound v=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='v.ar' )
		( cmd='compound vx=( compound v=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='v.ar' )
		( cmd='compound vx=( compound v=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='v.ar' )
		( cmd='compound vx=( compound v=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='v.ar' )
		( cmd='compound vx=( compound v=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='v.ar' )
		( cmd='compound vx=( compound v=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='v.ar' )

		# subtests3: Same as subtests1 but variable "va" is an indexed array
		( cmd='compound vx=( compound -a va=( [3]=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[3].ar' )
		( cmd='compound vx=( compound -a va=( [3]=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)' 		arrefname='va[3].ar' )
		( cmd='compound vx=( compound -a va=( [3]=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='va[3].ar' )
		( cmd='compound vx=( compound -a va=( [3]=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[3].ar' )
		( cmd='compound vx=( compound -a va=( [3]=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[3].ar' )
		( cmd='compound vx=( compound -a va=( [3]=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='va[3].ar' )

		# subtests4: Same as subtests1 but variable "va" is an 2d indexed array
		( cmd='compound vx=( compound -a va=( [3][17]=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='va[3][17].ar' )
 		( cmd='compound vx=( compound -a va=( [3][17]=( float	-A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='va[3][17].ar' )
 		( cmd='compound vx=( compound -a va=( [3][17]=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)' arrefname='va[3][17].ar' )
 		( cmd='compound vx=( compound -a va=( [3][17]=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='va[3][17].ar' )
 		( cmd='compound vx=( compound -a va=( [3][17]=( float	-A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'		arrefname='va[3][17].ar' )
 		( cmd='compound vx=( compound -a va=( [3][17]=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)' arrefname='va[3][17].ar' )

		# subtests5: Same as subtests1 but variable "va" is an associative array
		( cmd='compound vx=( compound -A va=( [l]=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[l].ar' )
		( cmd='compound vx=( compound -A va=( [l]=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[l].ar' )
		( cmd='compound vx=( compound -A va=( [l]=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -C vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='va[l].ar' )
		( cmd='compound vx=( compound -A va=( [l]=( integer -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[l].ar' )
		( cmd='compound vx=( compound -A va=( [l]=( float   -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=9.*)&(.*\\[aa\\]=4.*)'			arrefname='va[l].ar' )
		( cmd='compound vx=( compound -A va=( [l]=( typeset -A ar=( [aa]=4 [bb]=9 ) ; ) ; ) ; ) ; print -v vx' stdoutpattern=$'~(Alr)(.*\\[bb\\]=["\']*9.*)&(.*\\[aa\\]=["\']*4.*)'	arrefname='va[l].ar' )
	)

	for testid in "${!tests[@]}" ; do
		nameref test=tests[testid]
		typeset testname="test2/${testid}"

	        out.stderr="${ { out.stdout="${ ${SHELL} -c "${test.cmd}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

        	(( out.res == 0 )) || err_exit "${testname}: Test shell returned with exit code ${out.res}"
        	[[ "${out.stdout}" == ${test.stdoutpattern} ]] || err_exit "${testname}: Expected match for ${test.stdoutpattern}, got $(printf "%q\n" "${out.stdout}")"
        	[[ "${out.stderr}" == ""                    ]] || err_exit "${testname}: Expected empty stderr, got $(printf "%q\n" "${out.stderr}")"
	
		read -C val <<<"${out.stdout}" || err_exit "${testname}: read -C val failed with exit code $?"
		nameref ar="val.${test.arrefname}"
		(( ar[aa] == 4 )) || err_exit "${testname}: Expected ar[aa] == 4, got ${ar[aa]}"
		(( ar[bb] == 9 )) || err_exit "${testname}: Expected ar[bb] == 9, got ${ar[bb]}"
	done

	return 0
}

test6

function test_3D_array_read_C
{
        compound out=( typeset stdout stderr ; integer res )
	integer i
	typeset -r -a tests=(
		# ast-ksh.2010-03-09 will print "ksh93[1]: read: line 4: 0[0]: invalid variable name" for 3D arrays passed to read -C
		'compound c=( typeset -a x ) ; for (( i=0 ; i < 3 ; i++ )) ; do for (( j=0 ; j < 3 ; j++ )) ; do for (( k=0 ; k < 3 ; k++ )) ; do c.x[i][j][k]="$i$j$k" ; done; done; done ; unset c.x[2][0][1] ; print -v c | read -C dummy'

		# same test, 4D, fails with 'ksh[1]: read: line 4: 0: invalid variable name'
		'compound c=( typeset -a x ) ; for (( i=0 ; i < 3 ; i++ )) ; do for (( j=0 ; j < 3 ; j++ )) ; do for (( k=0 ; k < 3 ; k++ )) ; do for (( l=0 ; l < 3 ; l++ )) ; do c.x[i][j][k][l]="$i$j$k$l" ; done; done; done ; done ; unset c.x[2][0][1][2] ; print -v c | read -C dummy'
	)

	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -c "${tests[i]}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	        [[ "${out.stdout}" == '' ]] || err_exit "$0/${i}: Expected empty stdout, got $(printf '%q\n' "${out.stdout}")"
        	[[ "${out.stderr}" == '' ]] || err_exit "$0/${i}: Expected empty stderr, got $(printf '%q\n' "${out.stderr}")"
	done
	
	return 0
}


function test_access_2Darray_in_type_in_compound
{
        compound out=( typeset stdout stderr ; integer res )
	integer i
	typeset -r -a tests=(
		# ast-ksh.2010-03-09 will print 'ksh: line 1: l.c.x[i][j]=: no parent'
		'typeset -T c_t=(typeset -a x) ; compound l=( c_t c ) ; for ((i=0;i<3;i++));do for ((j=0;j<3;j++));do l.c.x[i][j]="" ; done; done; print -v l | read -C dummy'
	)

	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -c "${tests[i]}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	        [[ "${out.stdout}" == '' ]] || err_exit "$0/${i}: Expected empty stdout, got $(printf '%q\n' "${out.stdout}")"
        	[[ "${out.stderr}" == '' ]] || err_exit "$0/${i}: Expected empty stderr, got $(printf '%q\n' "${out.stderr}")"
	done
	
	return 0
}

function test_read_type_crash
{
        compound out=( typeset stdout stderr ; integer res )
	typeset -r test='
typeset -T field_t=(
	typeset -a f
	
	function reset
	{
		integer i j
		
		for (( i=0 ; i < 3 ; i++ )) ; do
			for (( j=0 ; j < 3 ; j++ )) ; do
				_.f[i][j]=""
			done
		done
		return 0
	}
	
	function enumerate_empty_fields
	{
		integer i j
		
		for (( i=0 ; i < 3 ; i++ )) ; do
			for (( j=0 ; j < 3 ; j++ )) ; do
				[[ "${_.f[i][j]}" == "" ]] && printf "[%d][%d]\n" i j
			done
		done
		return 0
	}
	
	function setf
	{
		_.f[$1][$2]="$3"
	}
)

set -o nounset

compound c1=( field_t x )

c1.x.reset

print -v c1 | read -C c2
print -v c2
'

	out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -c "${test}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

        [[ "${out.stdout}" != '' ]] || err_exit "$0: Expected nonempty stdout."
       	[[ "${out.stderr}" == '' ]] || err_exit "$0: Expected empty stderr, got $(printf '%q\n' "${out.stderr}")"

	if [[ -f 'core' && -x '/usr/bin/pstack' ]] ; then
		pstack 'core'
		rm 'core'
	fi

	return 0
}


function test_read_C_into_array
{
        compound out=( typeset stdout stderr ; integer res )
	# fixme:
	# - The tests should cover 3D and 5D indexed arrays and namerefs to sub-dimensions of a 5D indexed array
	compound -r -a tests=(
		( cmd='             typeset -a -C l   ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l[4] ;      print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )
		( cmd='             typeset -a -C l   ; nameref l4=l[4] ;      printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )

		( cmd='             typeset -a -C l   ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l[4][6] ;   print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' ) )
		( cmd='             typeset -a -C l   ; nameref l4=l[4][6] ;   printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' ) )

		( cmd='             typeset -a -C l   ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l[4][6][9][11][15] ;   print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' '~(X)(.+\[9\].+)&(.+\[11\].+)&(.+\[15\].+)' ) )
		( cmd='             typeset -a -C l   ; nameref l4=l[4][6][9][11][15] ;   printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' '~(X)(.+\[9\].+)&(.+\[11\].+)&(.+\[15\].+)' ) )

		( cmd='             typeset -A -C l   ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l[4] ;      print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )
		( cmd='             typeset -A -C l   ; nameref l4=l[4] ;      printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v l' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )
		( cmd='compound c ; typeset -a -C c.l ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C c.l[4] ;    print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )
		( cmd='compound c ; typeset -a -C c.l ; nameref l4=c.l[4] ;    printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )

		( cmd='compound c ; typeset -a -C c.l ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C c.l[4][6] ; print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' ) )
		( cmd='compound c ; typeset -a -C c.l ; nameref l4=c.l[4][6] ; printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' ) )

		( cmd='compound c ; typeset -a -C c.l ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C c.l[4][6][9][11][15] ; print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' '~(X)(.+\[9\].+)&(.+\[11\].+)&(.+\[15\].+)'  ) )
		( cmd='compound c ; typeset -a -C c.l ; nameref l4=c.[4][6][9][11][15] ; printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;         print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)&(.+\[6\].+)' '~(X)(.+\[9\].+)&(.+\[11\].+)&(.+\[15\].+)'  ) )

		( cmd='compound c ; typeset -A -C c.l ;                        printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C c.l[4] ;    print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )
		( cmd='compound c ; typeset -A -C c.l ; nameref l4=c.l[4] ;    printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l4 ;        print -v c' typeset -a stdoutpattern=( '~(X)(.+b=1.+)&(.+\[4\].+)' ) )
	)
	typeset cmd
	typeset pat
	integer i
	
	compound -a test_variants

	# build list of variations of the tests above
	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		nameref tst=tests[i]
		
		# plain test
		cmd="${tst.cmd}"	
		test_variants+=( testname="${0}/${i}/plain" cmd="$cmd" typeset -a stdoutpattern=( "${tst.stdoutpattern[@]}" ) )

		# test with "read -C" in a function
		cmd="${tst.cmd/~(E)read[[:space:]]+-C[[:space:]]+([[:alnum:]]+)[[:space:]]+\;/{ function rf { nameref val=\$1 \; read -C val \; } \; rf \1 \; } \; }"
		test_variants+=( testname="${0}/${i}/read_in_function" cmd="$cmd" typeset -a stdoutpattern=( "${tst.stdoutpattern[@]}" ) )

		# test with "read -C" in a nested function
		cmd="${tst.cmd/~(E)read[[:space:]]+-C[[:space:]]+([[:alnum:]]+)[[:space:]]+\;/{ function rf2 { nameref val=\$1 \; read -C val \; } \; function rf { nameref val=\$1 \; rf2 val \; } \; rf \1 \; } \; }"
		test_variants+=( testname="${0}/${i}/read_in_nested_function" cmd="$cmd" typeset -a stdoutpattern=( "${tst.stdoutpattern[@]}" ) )

		# test with "read -C" in a nested function with target variable
		# being a function-local variable of function "main"
		cmd='function rf2 { nameref val=$1 ; read -C val ; } ; function rf { nameref val=$1 ; rf2 val ; } ; function main { '
		cmd+="${tst.cmd/~(E)read[[:space:]]+-C[[:space:]]+([[:alnum:]]+)[[:space:]]+\;/rf \1 \; }"
		cmd+=' ; } ; main'
		test_variants+=( testname="${0}/${i}/read_into_localvar_in_nested_function" cmd="$cmd" typeset -a stdoutpattern=( "${tst.stdoutpattern[@]}" ) )
	done

	# run test variants
	for (( i=0 ; i < ${#test_variants[@]} ; i++ )) ; do
		nameref tv=test_variants[i]

		out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -o errexit -c "${tv.cmd}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"
 
		for pat in "${tv.stdoutpattern[@]}" ; do
			[[ "${out.stdout}" == ${pat} ]] || err_exit "${tv.testname}: Expected stdout of $(printf '%q\n' "${tv.cmd}") to match $(printf '%q\n' "${pat}"), got $(printf '%q\n' "${out.stdout}")"
		done
		[[ "${out.stderr}" == '' ]] || err_exit "${tv.testname}: Expected empty stderr for $(printf '%q\n' "${tv.cmd}"), got $(printf '%q\n' "${out.stderr}")"
		(( out.res == 0 )) || err_exit "${tv.testname}: Unexpected exit code ${out.res} for $(printf '%q\n' "${tv.cmd}")"
	done

	return 0
}


# This test checks whether reading a compound variable value with
# "read -C var" which contains special shell keywords or aliases
# like "functions", "alias", "!" etc. in a string array causes the
# shell to produce errors like this:
# -- snip --
# $ ksh93 -c 'print "( compound -A a1=( [4]=( typeset -a x=( alias ) ) ) ;
# compound -A a2=( [4]=( typeset -a x=( ! ! ! alias ) ) ) )" | read -C c ; print -v c' 1>/dev/null
# ksh93[1]: alias: c.a1[4].x: compound assignment requires sub-variable name
# -- snip --
# A 2nd issue indirectly tested here was that simple indexed string array
# declarations in a function with the same special keywords did not work
# either.
# This happened in ast-ksh.2010-11-12 or older.
function test_read_C_special_shell_keywords
{
	typeset -r -a testcmdpatterns=(
		# this was the original testcase
		'print "( compound -A a1=( [4]=( typeset -a x=( %keyword% ) ) ) ; compound -A a2=( [4]=( typeset -a x=( ! ! ! alias ) ) ) )" | read -C c ; print "X${c.a1[4].x[0]}X"'
		# same as above but uses indexed arrays instead of associative arrays
		'print "( compound -a a1=( [4]=( typeset -a x=( %keyword% ) ) ) ; compound -a a2=( [4]=( typeset -a x=( ! ! ! alias ) ) ) )" | read -C c ; print "X${c.a1[4].x[0]}X"'
		# same as first testcase but uses a blank in the array index value
		$'print "( compound -A a1=( [\'hello world\']=( typeset -a x=( %keyword% ) ) ) ; compound -A a2=( [\'hello world\']=( typeset -a x=( ! ! ! alias ) ) ) )" | read -C c ; print "X${c.a1[\'hello world\'].x[0]}X"'
	)
	typeset -r -a shell_special_words=(
		'alias'
		'compound'
		'function'
		'functions'
		'integer'
		'local'
		'namespace'
		'typeset'
		'SECONDS'
		'.sh.version'
		'!'
	)
	integer spwi # shell_special_words index
	integer tcpi # testcmdpatterns index
	typeset testcmd
	typeset testname
	typeset shkeyword
        compound out=( typeset stdout stderr ; integer res )
	
	for (( tcpi=0 ; tcpi < ${#testcmdpatterns[@]} ; tcpi++ )) ; do
		for (( spwi=0 ; spwi < ${#shell_special_words[@]} ; spwi++ )) ; do
			shkeyword=${shell_special_words[spwi]}
			testcmd="${testcmdpatterns[tcpi]//%keyword%/${shkeyword}}"
			testname="${0}/${tcpi}/${spwi}/"
	
			out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -o errexit -c "${testcmd}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

        		[[ "${out.stdout}" == "X${shkeyword}X" ]] || err_exit "${testname}: Expected stdout to match $(printf '%q\n' "X${shkeyword}X"), got $(printf '%q\n' "${out.stdout}")"
			[[ "${out.stderr}" == '' ]] || err_exit "${testname}: Expected empty stderr, got $(printf '%q\n' "${out.stderr}")"
			(( out.res == 0 )) || err_exit "${testname}: Unexpected exit code ${out.res}"
		done
	done

	return 0
}


test_3D_array_read_C
test_access_2Darray_in_type_in_compound
test_read_type_crash
test_read_C_into_array
test_read_C_special_shell_keywords


# tests done
exit $((Errors<125?Errors:125))
