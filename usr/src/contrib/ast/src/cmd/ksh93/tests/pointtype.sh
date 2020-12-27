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

typeset -T Pt_t=(
	float x=1
	float y=0
	len()
	{
		print -r $((sqrt(_.x*_.x + _.y*_.y)))
	}
)

for ((i=0; i < 100; i++))
do
Pt_t p
[[ ${p.x} == 1 ]] || err_exit '${p[x]} is not 1'
(( p.x == 1 )) || err_ext 'p[x] is not 1'
[[ $(p.len) == 1 ]] || err_exit '$(p.len) != 1'
[[ ${p.len} == 1 ]] || err_exit '${p.len} != 1'
(( p.len == 1  )) || err_exit '((p.len != 1))'
Pt_t q=(y=2)
(( q.x == 1 )) || err_exit 'q.x is not 1'
(( (q.len - sqrt(5)) < 10e-10 )) || err_exit 'q.len != sqrt(5)'
q.len()
{
	print -r $((abs(_.x)+abs(_.y) ))
}
(( q.len == 3 )) || err_exit 'q.len is not 3'
p=q
[[ ${p.y} == 2 ]] || err_exit '${p[y]} is not 2'
[[ ${@p} == Pt_t ]] || err_exit 'type of p is not Pt_t'
[[ ${@q} == Pt_t ]] || err_exit 'type of q is not Pt_t'
(( p.len == 3 )) || err_exit 'p.len is not 3'
unset p q
Pt_t pp=( (  x=3 y=4) (  x=5 y=12) (y=2) )
(( pp[0].len == 5 )) || err_exit 'pp[0].len != 5'
(( pp[1].len == 13 )) || err_exit 'pp[0].len != 12'
(( (pp[2].len - sqrt(5)) < 10e-10 )) || err_exit 'pp[2].len != sqrt(5)'
[[ ${pp[1]} == $'(\n\ttypeset -l -E x=5\n\ttypeset -l -E y=12\n)' ]] || err_exit '${pp[1] is not correct'
[[ ${!pp[@]} == '0 1 2' ]] || err_exit '${pp[@] != "0 1 2"'
pp+=( x=6 y=8)
(( pp[3].len == 10 )) || err_exit 'pp[3].len != 10'
[[ ${!pp[@]} == '0 1 2 3' ]] || err_exit '${pp[@] != "0 1 2 3"'
pp[4]=pp[1]
[[ ${pp[4]} == $'(\n\ttypeset -l -E x=5\n\ttypeset -l -E y=12\n)' ]] || err_exit '${pp[4] is not correct'
unset pp
Pt_t pp=( [one]=(  x=3 y=4) [two]=(  x=5 y=12) [three]=(y=2) )
(( pp[one].len == 5 )) || err_exit 'pp[one].len != 5'
(( pp[two].len == 13 )) || err_exit 'pp[two].len != 12'
[[ ${pp[two]} == $'(\n\ttypeset -l -E x=5\n\ttypeset -l -E y=12\n)' ]] || err_exit '${pp[two] is not correct'
[[ ${!pp[@]} == 'one three two' ]] || err_exit '${pp[@] != "one three two"'
[[ ${@pp[1]} == Pt_t ]] || err_exit 'type of pp[1] is not Pt_t'
unset pp
done
# redefinition of point
typeset -T Pt_t=(
	Pt_t _=(x=3 y=6)
	float z=2
	len()
	{
		print -r $((sqrt(_.x*_.x + _.y*_.y + _.z*_.z)))
	}
)
Pt_t p
[[ ${p.y} == 6 ]] || err_exit '${p.y} != 6'
(( p.len == 7 )) || err_exit '((p.len !=7))'

z=()
Pt_t -a z.p
z.p[1]=(y=2)
z.p[2]=(y=5)
z.p[3]=(x=6 y=4)
eval y="$z"
[[ $y == "$z" ]] || err_exit 'expansion of indexed array of types is incorrect'
eval "$(typeset -p y)"
[[ $y == "$z" ]] || err_exit 'typeset -p z for indexed array of types is incorrect'
unset z y
z=()
Pt_t -A z.p
z.p[1]=(y=2)
z.p[2]=(y=5)
z.p[3]=(x=6 y=4)
eval y="$z"
[[ $y == "$z" ]] || err_exit 'expansion of associative array of types is incorrect'
eval "$(typeset -p y)"
[[ $y == "$z" ]] || err_exit 'typeset -p z for associative of types is incorrect'
unset z y

typeset -T A_t=(
        Pt_t  -a  b
)
typeset -T B_t=(
        Pt_t  -A  b
)
A_t r
r.b[1]=(y=2)
r.b[2]=(y=5)
eval s="$r"
[[ $r == "$s" ]] || err_exit 'expansion of type containing index array of types is incorrect'
eval "$(typeset -p s)"
[[ $y == "$z" ]] || err_exit 'typeset -p z for type containing index of types is incorrect'
unset r s
B_t r
r.b[1]=(y=2)
r.b[2]=(y=5)
eval s="$r"
[[ $r == "$s" ]] || err_exit 'expansion of type containing index array of types is incorrect'
eval "$(typeset -p s)"
[[ $y == "$z" ]] || err_exit 'typeset -p z for type containing index of types is incorrect'

exit $((Errors<125?Errors:125))
