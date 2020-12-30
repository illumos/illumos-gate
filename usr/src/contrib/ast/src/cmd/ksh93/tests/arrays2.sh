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
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0
for	((i=0; i < 4; i++ ))
do	for	((j=0; j < 5; j++ ))
	do	a[i][j]=$i$j
	done
done
for	((i=0; i < 4; i++ ))
do	for	((j=0; j < 5; j++ ))
	do	[[ ${a[i][j]} == "$i$j" ]] || err_exit "\${a[$i][$j]} != $i$j"
	done
done
for	((i=0; i < 4; i++ ))
do	j=0;for k in ${a[i][@]}
	do	[[ $k == "$i$j" ]] || err_exit "\${a[i][@]} != $i$j"
		(( j++ ))
	done
done
unset a
a=(
	( 00 01 02 03 04 )
	( 10 11 12 13 14 15)
	( 20 21 22 23 24 )
	( 30 31 32 33 34 )
)

function check
{
	nameref a=$1
	nameref b=a[2]
	typeset c=$1
	integer i j
	for	((i=0; i < 4; i++ ))
	do	for	((j=0; j < 5; j++ ))
		do	[[ ${a[$i][$j]} == "$i$j" ]] || err_exit "\${$c[$i][$j]} != $i$j"
		done
	done
	(( ${#a[@]} == 4 )) || err_exit "\${#$c[@]} not 4"
	(( ${#a[0][@]} == 5 )) || err_exit "\${#$c[0][@]} not 5"
	(( ${#a[1][@]} == 6 )) || err_exit "\${#$c[1][@]} not 6"
	set -s -- ${!a[@]}
	[[ ${@} == '0 1 2 3' ]] || err_exit "\${!$c[@]} not 0 1 2 3"
	set -s -- ${!a[0][@]}
	[[ ${@} == '0 1 2 3 4' ]] || err_exit "\${!$c[0][@]} not 0 1 2 3 4"
	set -s -- ${!a[1][@]}
	[[ ${@} == '0 1 2 3 4 5' ]] || err_exit "\${!$c[1][@]} not 0 1 2 3 4 5"
	[[ $a == 00 ]] || err_exit  "\$$c is not 00"
	[[ ${a[0]} == 00 ]] || err_exit  "\${$a[0]} is not 00"
	[[ ${a[0][0]} == 00 ]] || err_exit  "${a[0][0]} is not 00"
	[[ ${a[0][0][0]} == 00 ]] || err_exit  "\${$c[0][0][0]} is not 00"
	[[ ${a[0][0][1]} == '' ]] || err_exit  "\${$c[0][0][1]} is not empty"
	[[ ${b[3]} == 23 ]] || err_exit "${!b}[3] not = 23"
}

check a

unset a
typeset -A a
for	((i=0; i < 4; i++ ))
do	for	((j=0; j < 5; j++ ))
	do	a[$i][j]=$i$j
	done
done
for	((i=0; i < 4; i++ ))
do	for	((j=0; j < 5; j++ ))
	do	[[ ${a[$i][j]} == "$i$j" ]] || err_exit "\${a[$i][$j]} == $i$j"
	done
done
a[1][5]=15
b=(
	[0]=( 00 01 02 03 04 )
	[1]=( 10 11 12 13 14 15)
	[2]=( 20 21 22 23 24 )
	[3]=( 30 31 32 33 34 )
)
check b
[[ ${a[1][@]} == "${b[1][@]}" ]] || err_exit "a[1] not equal to b[1]"
c=(
	[0]=( [0]=00 [1]=01 [2]=02 [3]=03 [4]=04 )
	[1]=( [0]=10 [1]=11 [2]=12 [3]=13 [4]=14 [5]=15)
	[2]=( [0]=20 [1]=21 [2]=22 [3]=23 [4]=24 )
	[3]=( [0]=30 [1]=31 [2]=32 [3]=33 [4]=34 )
)
check c
typeset -A d
d[0]=( [0]=00 [1]=01 [2]=02 [3]=03 [4]=04 )
d[1]=( [0]=10 [1]=11 [2]=12 [3]=13 [4]=14 [5]=15)
d[2]=( [0]=20 [1]=21 [2]=22 [3]=23 [4]=24 )
d[3]=( [0]=30 [1]=31 [2]=32 [3]=33 [4]=34 )
check d
unset a b c d
[[ ${a-set} ]] || err_exit "a is set after unset"
[[ ${b-set} ]] || err_exit "b is set after unset"
[[ ${c-set} ]] || err_exit "c is set after unset"
[[ ${d-set} ]] || err_exit "c is set after unset"

$SHELL 2> /dev/null <<\+++ ||  err_exit 'input of 3 dimensional array not working'
typeset x=(
	( (g G) (h H) (i I) )
	( (d D) (e E) (f F) )
	( (a A) (b B) (c C) )
)
[[ ${x[0][0][0]} == g ]] || err_exit '${x[0][0][0]} == G'
[[ ${x[1][1][0]} == e ]] || err_exit '${x[1][1][0]} == e'
[[ ${x[1][1][1]} == E ]] || err_exit '${x[2][2][1]} == C'
[[ ${x[0][2][1]} == I ]] || err_exit '${x[0][2][1]} == I'
+++

typeset -a -si x=( [0]=(1 2 3) [1]=(4 5 6) [2]=(7 8 9) )
[[ ${x[1][1]} == 5 ]] || err_exit 'changing two dimensional indexed array to short integer failed'
unset x
typeset -A -si x=( [0]=(1 2 3) [1]=(4 5 6) [2]=(7 8 9) )
[[ ${x[1][2]} == 6 ]] || err_exit 'changing two dimensional associative array to short integer failed'

unset ar x y
integer -a ar
integer i x y
for (( i=0 ; i < 100 ; i++ ))
do	(( ar[y][x++]=i ))
	(( x > 9 )) && (( y++ , x=0 ))
done
[[ ${#ar[0][*]} == 10 ]] || err_exit "\${#ar[0][*]} is '${#ar[0][*]}', should be 10"
[[ ${#ar[*]} == 10 ]] || err_exit  "\${#ar[*]} is '${#ar[*]}', should be 10"
[[ ${ar[5][5]} == 55 ]] || err_exit "ar[5][5] is '${ar[5][5]}', should be 55"

unset ar
integer -a ar
x=0 y=0
for (( i=0 ; i < 81 ; i++ ))
do	nameref ar_y=ar[$y]
	(( ar_y[x++]=i ))
	(( x > 8 )) && (( y++ , x=0 ))
	typeset +n ar_y
done
[[ ${#ar[0][*]} == 9 ]] || err_exit "\${#ar[0][*]} is '${#ar[0][*]}', should be 9"
[[ ${#ar[*]} == 9 ]] || err_exit  "\${#ar[*]} is '${#ar[*]}', should be 9"
[[ ${ar[4][4]} == 40 ]] || err_exit "ar[4][4] is '${ar[4][4]}', should be 40"

$SHELL 2> /dev/null -c 'compound c;float -a c.ar;(( c.ar[2][3][3] = 5))' || 'multi-dimensional arrays in arithemtic expressions not working'

expected='typeset -a -l -E c.ar=([2]=([3]=([3]=5) ) )'
unset c
float c.ar
c.ar[2][3][3]=5
[[ $(typeset -p c.ar) == "$expected" ]] || err_exit "c.ar[2][3][3]=5;typeset -c c.ar expands to $(typeset -p c.ar)"

unset values
float -a values=( [1][3]=90 [1][4]=89 )
function fx
{
	nameref arg=$1
	[[ ${arg[0..5]} == '90 89' ]] || err_exit '${arg[0..5]} not correct where arg is a nameref to values[1]'
}
fx values[1]

function test_short_integer
{
        compound out=( typeset stdout stderr ; integer res )
	compound -r -a tests=(
		( cmd='integer -s -r -a x=( 1 2 3 ) ; print "${x[2]}"' stdoutpattern='3' )
		( cmd='integer -s -r -A x=( [0]=1 [1]=2 [2]=3 ) ; print "${x[2]}"' stdoutpattern='3' )
		# 2D integer arrays: the following two tests crash for both "integer -s" and "integer"
		( cmd='integer    -r -a x=( [0]=( [0]=1 [1]=2 [2]=3 ) [1]=( [0]=4 [1]=5 [2]=6 ) [2]=( [0]=7 [1]=8 [2]=9 ) ) ; print "${x[1][1]}"' stdoutpattern='5' )
		( cmd='integer -s -r -a x=( [0]=( [0]=1 [1]=2 [2]=3 ) [1]=( [0]=4 [1]=5 [2]=6 ) [2]=( [0]=7 [1]=8 [2]=9 ) ) ; print "${x[1][1]}"' stdoutpattern='5' )
   	)
	typeset testname
	integer i

	for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
		nameref tst=tests[i]
		testname="${0}/${i}"

		out.stderr="${ { out.stdout="${ ${SHELL} -o nounset -o errexit -c "${tst.cmd}" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	        [[ "${out.stdout}" == ${tst.stdoutpattern}      ]] || err_exit "${testname}: Expected stdout to match $(printf '%q\n' "${tst.stdoutpattern}"), got $(printf '%q\n' "${out.stdout}")"
       		[[ "${out.stderr}" == ''			]] || err_exit "${testname}: Expected empty stderr, got $(printf '%q\n' "${out.stderr}")"
		(( out.res == 0 )) || err_exit "${testname}: Unexpected exit code ${out.res}"
	done
	
	return 0
}
# run tests
test_short_integer

typeset -a arr=( ( 00 ) ( 01 ) ( 02 ) ( 03 ) ( 04 ) ( 05 ) ( 06 ) ( 07 ) ( 08 ) ( 09 ) ( 10 ) )
typeset -i i=10 j=0
{  y=$( echo ${arr[i][j]} ) ;} 2> /dev/null
[[ $y == 10 ]] || err_exit '${arr[10][0] should be 10 '

unset cx l
compound cx
typeset -a cx.ar[4][4]
print -v cx > /dev/null
print -v cx | read -C l 2> /dev/null || err_exit 'read -C fails from output of print -v'
[[ ${cx%cx=} ==  "${l%l=}" ]] || err_exit 'print -v for compound variable with fixed 2d array not working'

exit $((Errors<125?Errors:125))
