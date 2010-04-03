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
{
x=abc
x+=def ;} 2> /dev/null
if	[[ $x != abcdef ]]
then	err_exit 'abc+def != abcdef'
fi
integer i=3
{ i+=4;} 2> /dev/null
if	(( i != 7 ))
then	err_exit '3+4!=7'
fi
iarray=( one two three )
{ iarray+= (four five six) ;} 2> /dev/null
if	[[ ${iarray[@]} != 'one two three four five six' ]]
then	err_exit 'index array append fails'
fi
unset iarray
iarray=one
{ iarray+= (four five six) ;} 2> /dev/null
if	[[ ${iarray[@]} != 'one four five six' ]]
then	err_exit 'index array append to scalar fails'
fi
typeset -A aarray
aarray=( [1]=1 [3]=4 [xyz]=xyz )
aarray+=( [2]=2 [3]=3 [foo]=bar )
if	[[ ${aarray[3]} != 3 ]]
then	err_exit 'associative array append fails'
fi
if	[[ ${#aarray[@]} != 5 ]]
then	err_exit 'number of elements of associative array append fails'
fi
point=(x=1 y=2)
point+=( y=3 z=4)
if	[[ ${point.y} != 3 ]]
then	err_exit 'compound append fails'
fi
if	[[ ${point.x} != 1 ]]
then	err_exit 'compound append to compound variable unsets existing variables'
fi
unset foo
foo=one
foo+=(two)
if	[[ ${foo[@]} != 'one two' ]]
then	err_exit 'array append to non array variable fails'
fi
unset foo
foo[0]=(x=3)
foo+=(x=4)
[[ ${foo[1].x} == 4 ]] || err_exit 'compound append to index array not working'
[[ ${foo[0].x} == 3 ]] || err_exit 'compound append to index array unsets existing variables'
exit $((Errors))
