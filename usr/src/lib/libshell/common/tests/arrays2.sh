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
exit $((Errors))
