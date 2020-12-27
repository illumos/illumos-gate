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
	(( Errors+=1 ))
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0
enum Color_t=(red green blue orange yellow)
enum -i Sex_t=(Male Female)
for ((i=0; i < 1000; i++))
do
Color_t x
[[ $x == red ]] || err_exit 'Color_t does not default to red'
x=orange
[[ $x == orange ]] || err_exit '$x should be orange'
( x=violet) 2> /dev/null && err_exit 'x=violet should fail'
x[2]=green
[[ ${x[2]} == green ]] || err_exit '${x[2]} should be green'
(( x[2] == 1 )) || err_exit '((x[2]!=1))'
[[ $((x[2])) == 1 ]] || err_exit '$((x[2]))!=1'
[[ $x == orange ]] || err_exit '$x is no longer orange'
Color_t -A y
y[foo]=yellow
[[ ${y[foo]} == yellow ]] || err_exit '${y[foo]} != yellow'
(( y[foo] == 4 )) || err_exit '(( y[foo] != 4))'
unset y
typeset -a [Color_t] z
z[green]=xyz
[[ ${z[green]} == xyz ]] || err_exit '${z[green]} should be xyz'
[[ ${z[1]} == xyz ]] || err_exit '${z[1]} should be xyz'
z[orange]=bam
[[ ${!z[@]} == 'green orange' ]] || err_exit '${!z[@]} == "green orange"'
unset x
Sex_t x
[[ $x == Male ]] || err_exit 'Sex_t not defaulting to Male'
x=female
[[ $x == Female ]] || err_exit 'Sex_t not case sensitive'
unset x y z
done
(
typeset -T X_t=( typeset name=aha )
typeset -a[X_t] arr
) 2> /dev/null
[[ $? == 1 ]] || err_exit 'typeset -a[X_t] should generate an error message when X-t is not an enumeriation type'

typeset -a [Color_t] arr
arr[green]=foo
[[ ${arr[1]} == ${arr[green]}  ]] || err_exit 'arr[1] != arr[green]'
read -A arr <<<  'x y z xx yy'
[[ ${arr[1]} == ${arr[green]}  ]] || err_exit 'arr[1] != arr[green] after read'

exit $((Errors<125?Errors:125))
