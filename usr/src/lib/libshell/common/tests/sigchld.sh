########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2008 AT&T Intellectual Property          #
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

float DELAY=${1:-0.5}
integer FOREGROUND=10 BACKGROUND=2 Errors=0

s=$($SHELL -c '
integer i foreground=0 background=0
float delay='$DELAY' d=0 s=0

set --errexit

trap "(( background++ ))" CHLD

(( d = delay ))
for ((i = 0; i < '$BACKGROUND'; i++))
do	sleep $d &
	(( d *= 4 ))
	(( s += d ))
done
for ((i = 0; i < '$FOREGROUND'; i++))
do	(( foreground++ ))
	sleep $delay
	(( s -= delay ))
	$SHELL -c : > /dev/null # foreground does not generate SIGCHLD
done
if	(( (s += delay) < 1 ))
then	(( s = 1 ))
fi
sleep $s
wait
print foreground=$foreground background=$background
') || err_exit "test loop failed"

eval $s

(( foreground == FOREGROUND )) || err_exit "expected $FOREGROUND foreground -- got $foreground (DELAY=$DELAY)"
(( background == BACKGROUND )) || err_exit "expected $BACKGROUND background -- got $background (DELAY=$DELAY)"

exit $((Errors))
