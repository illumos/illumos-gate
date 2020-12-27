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
[[ $t == "$d" ]] || err_exit "printf %T != Time_t -- expected '$d', got '$t'"
(( t == s )) || err_exit "numeric Time_t failed -- expected '$s', got '$t'"
t._='%#'
[[ $t == $s ]] || err_exit "t._='%#' failed -- expected '$s', got '$t'"
unset t
Time_t tt=(yesterday today tomorrow)
tt[3]=2pm
[[ ${!tt[@]} == '0 1 2 3' ]] || err_exit "indexed array subscript names failed -- expected '0 1 2 3', got '${!tt[@]}'"
[[ ${tt[0]} == *+00:00 ]] || err_exit "tt[0] failed -- expected 00:00, got '${tt[0]##*+}'"
[[ ${tt[1]} == *+00:00 ]] || err_exit "tt[1] failed -- expected 00:00, got '${tt[1]##*+}'"
[[ ${tt[2]} == *+00:00 ]] || err_exit "tt[2] failed -- expected 00:00, got '${tt[2]##*+}'"
[[ ${tt[3]} == *+14:00 ]] || err_exit "tt[3] failed -- expected 14:00, got '${tt[3]##*+}'"
unset tt
Time_t tt=('2008-08-11+00:00:00,yesterday' '2008-08-11+00:00:00,today' '2008-08-11+00:00:00,tomorrow')
tt[3]=9am
tt[4]=5pm
(( (tt[1] - tt[0]) == 24*3600 )) || err_exit "today-yesterday='$((tt[1] - tt[0]))' != 1 day"
(( (tt[2] - tt[1]) == 24*3600 )) || err_exit "tomorrow-today='$((tt[2] - tt[1]))' != 1 day"
(( (tt[4] - tt[3]) ==  8*3600 )) || err_exit "9am..5pm='$((tt[4] - tt[3]))' != 8 hours"
unset tt
Time_t tt=([yesterday]='2008-08-11+00:00:00,yesterday' [today]='2008-08-11+00:00:00,today' [tomorrow]='2008-08-11+00:00:00,tomorrow')
tt[2pm]='2008-08-11+00:00:00,2pm'
[[ ${tt[yesterday]} == *+00:00 ]] || err_exit "tt[yesterday] failed -- expected 00:00, got '${tt[yesterday]##*+}'"
[[ ${tt[today]} == *+00:00 ]] || err_exit "tt[today] failed -- expected 00:00, got '${tt[today]##*+}'"
[[ ${tt[tomorrow]} == *+00:00 ]] || err_exit "tt[tomorrow] failed -- expected 00:00, got '${tt[tomorrow]##*+}'"
[[ ${tt[2pm]} == *+14:00 ]] || err_exit "tt[2pm] failed -- expected 14:00, got '${tt[2pm]##*+}'"
(( (tt[today] - tt[yesterday] ) == 24*3600 )) || err_exit "tt[today]-tt[yesterday] failed -- expected 24*3600, got $(((tt[today]-tt[yesterday])/3600.0))*3600"
(( (tt[tomorrow] - tt[today] ) == 24*3600 )) || err_exit "tt[tomorrow]-tt[today] failed -- expected 24*3600, got $(((tt[tomorrow]-tt[today])/3600.0))*3600"
(( (tt[2pm] - tt[today] ) == 14*3600 )) || err_exit "tt[2pm]-tt[today] failed -- expected 14*3600, got $(((tt[2pm]-tt[today])/3600.0))*3600"
unset tt

exit $((Errors<125?Errors:125))
