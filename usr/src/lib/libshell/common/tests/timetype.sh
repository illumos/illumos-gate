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
	(( Errors+=1 ))
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0

typeset -T Time_t=(
	integer .=-1
	_='%F+%H:%M'
	get()
	{
		if      (( _ < 0 ))
		then	.sh.value=${ printf "%(${_._})T" now ;}
		else	.sh.value=${ printf "%(${_._})T" "#$((_))" ;}
		fi
	}
	set()
	{
		.sh.value=${ printf "%(%#)T" "${.sh.value}";}
	}
)

d=$(printf "%(%F+%H:%M)T" now)
integer s=$(printf "%(%#)T" "$d")
Time_t t=$d
[[ $t == "$d" ]] || err_exit 'printf %T and Time_t are different'
(( t == s )) || err_exit 'numerical  Time_t not correct'
t._='%#'
[[ $t == $s ]] || err_exit 'setting _ to %# not getting correct results'
unset t
Time_t tt=(yesterday today tomorrow)
tt[3]=2pm
[[ ${!tt[@]} == '0 1 2 3' ]] || err_exit 'indexed array subscript names not correct'
[[ ${tt[0]} == *+00:00 ]] || err_exit 'tt[0] is not yesterday'
[[ ${tt[1]} == *+00:00 ]] || err_exit 'tt[1] is not today'
[[ ${tt[2]} == *+00:00 ]] || err_exit 'tt[2] is not tomorrow'
[[ ${tt[3]} == *+14:00 ]] || err_exit 'tt[0] is not 2pm'
unset tt
Time_t tt=('2008-08-11+00:00:00,yesterday' '2008-08-11+00:00:00,today' '2008-08-11+00:00:00,tomorrow')
tt[3]=9am
tt[4]=5pm
(( (tt[1] - tt[0] ) == 24*3600 )) || err_exit  'today-yesterday not one day'
(( (tt[2] - tt[1] ) == 24*3600 )) || err_exit  'tomorrow-today not one day'
(( (tt[4] - tt[3] ) == 8*3600 )) || err_exit  '9am .. 5pm is not 8 hours'
unset tt
Time_t tt=([yesterday]='2008-08-11+00:00:00,yesterday' [today]='2008-08-11+00:00:00,today' [tomorrow]='2008-08-11+00:00:00,tomorrow')
tt[2pm]='2008-08-11+00:00:00,2pm'
[[ ${tt[yesterday]} == *+00:00 ]] || err_exit 'tt[yesterday] is not yesterday'
[[ ${tt[today]} == *+00:00 ]] || err_exit 'tt[today] is not today'
[[ ${tt[tomorrow]} == *+00:00 ]] || err_exit 'tt[tomorrow] is not tomorrow'
[[ ${tt[2pm]} == *+14:00 ]] || err_exit 'tt[2pm] is not 2pm'
(( (tt[today] - tt[yesterday] ) == 24*3600 )) || err_exit  'today-yesterday not one day'
(( (tt[tomorrow] - tt[today] ) == 24*3600 )) || err_exit  'tomorrow-today not one day'
(( (tt[2pm] - tt[today] ) == 14*3600 )) || err_exit  '2pm is not 14 hours'
unset tt
exit $Errors
