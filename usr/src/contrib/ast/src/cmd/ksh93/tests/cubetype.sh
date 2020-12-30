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
integer n=2

typeset -T Box_t=(
	float -h 'height in inches' x=2
	float -h 'width in inches' y=4
	comvar=(top=8 bottom=9)
	integer -S count=0
	items=(foo bar)
	colors=([wall]=blue [floor]=red)
	typeset name=unknown
	typeset -L6 status=INIT
	len()
	{
		print -r $((sqrt(_.x*_.x + _.y*_.y)))
		(( _.count++))
	}
	typeset -fh 'distance from the origin' len
	depth()
	{
		print 0
	}
	float x=3
)

for ((i=0; i < n; i++))
do
Box_t b=(name=box1)
exp=3 got=${b.x}
[[ "$got" == "$exp" ]] || err_exit "\${b.x} incorrect for iteration $i -- expected $exp, got '$got'"
exp=5 got=$(( b.len ))
(( got == exp )) || err_exit "b.len incorrect for iteration $i -- expected $exp, got '$got = sqrt(${b.x}*${b.x}+${b.y}*${b.y})'"
exp=5 got=${b.len}
[[ "$got" == "$exp" ]] || err_exit "\${b.len} incorrect for iteration $i -- expected $exp, got '$got = sqrt(${b.x}*${b.x}+${b.y}*${b.y})'"
exp=box1 got=${b.name}
[[ "$got" == "${exp}" ]] || err_exit "\${b.name} incorrect for iteration $i -- expected $exp, got '$got'"
exp=2 got=$(( b.count ))
(( got == exp )) || err_exit "b.count incorrect for iteration $i -- expected $exp, got '$got'"
exp=2 got=${b.count}
[[ "$got" == "$exp" ]] || err_exit "\${b.ccount} incorrect for iteration $i -- expected $exp, got '$got'"
b.colors[wall]=green
b.colors[door]=white
exp=3 got=${#b.colors[@]}
[[ "$got" == "$exp" ]] || err_exit "\${#b.colors[@]} incorrect for iteration $i -- expected $exp, got '$got'"
b.comvar.bottom=11
b.items[1]=bam
b.items[2]=extra
exp=3 got=${#b.items[@]}
[[ ${#b.items[@]} == 3 ]] || err_exit "\${#b.items[@]} incorrect for iteration $i -- expected $exp, got '$got'"
Box_t bb=b
bb.colors[desk]=orange
exp=4 got=${#b.colors[@]}
[[ ${#bb.colors[@]} == 4 ]] || err_exit "\${#bb.colors[@]} incorrect for iteration $i -- expected $exp, got '$got'"
unset b.colors
exp=2 got=${#b.colors[@]}
[[ ${#b.colors[@]} == 2 ]] || err_exit "\${#b.colors[@]} incorrect for iteration $i -- expected $exp, got '$got'"
unset b.items
exp=2 got=${#b.items[@]}
[[ ${#b.items[@]} == 2 ]] || err_exit "\${#b.items[@]} incorrect for iteration $i -- expected $exp, got '$got'"
unset bb.colors
exp=2 got=${#bb.colors[@]}
[[ ${#bb.colors[@]} == 2 ]] || err_exit "\${#bb.colors[@]} incorrect for iteration $i -- expected $exp, got '$got'"
unset bb.items
exp=2 got=${#bb.items[@]}
[[ ${#bb.items[@]} == 2 ]] || err_exit "\${#bb.items[@]} incorrect for iteration $i -- expected $exp, got '$got'"
[[ $b == "$bb" ]] || err_exit "\$b='$b' != \$bb='$bb'"
b.count=0
unset b bb
done

typeset -T Cube_t=(
	Box_t	_=(y=5)
	float	z=1
	depth()
	{
		print -r -- $((_.z))
	}
	len()
	{
		print -r $((sqrt(_.x*_.x + _.y*_.y + _.z*_.z)))
		(( _.count++))
	}
	float x=8
	fun()
	{
		print 'hello world'
	}
)


for ((i=0; i < n; i++))
do
Box_t b=(name=box2)
[[ ${b.name} == box2 ]] || err_exit "\${b.name} incorrect -- expected box2, got '${b.name}'"
(( b.len == 5 )) || err_exit "b.len incorrect for box2 -- expected 5, got '$(( b.len ))'"
(( b.count == 1 )) || err_exit "b.count incorrect -- expected 1, got '$(( b.count ))'"
Cube_t c=(name=cube1)
[[ $c == $'(\n\ttypeset -l -E x=8\n\ttypeset -l -E y=5\n\tcomvar=(\n\t\ttop=8\n\t\tbottom=9\n\t)\n\ttypeset -S -l -i count=1\n\ttypeset -a items=(\n\t\tfoo\n\t\tbar\n\t)\n\ttypeset -A colors=(\n\t\t[floor]=red\n\t\t[wall]=blue\n\t)\n\tname=cube1\n\ttypeset -L 6 status=INIT\n\ttypeset -l -E z=1\n)' ]] || err_exit '$c not correct'
[[ ${c.x} == 8 ]] || err_exit '${c.x} != 8'
[[ ${c.depth} == 1 ]] || err_exit '${c.depth} != 1'
[[ ${c.name} == cube1 ]] || err_exit '${c.name} != cube1 '
[[ $(c.fun) == 'hello world' ]] || err_exit '$(c.fun) != "hello world"'
[[ ${c.fun} == 'hello world' ]] || err_exit '${c.fun} != "hello world"'
(( abs(c.len - sqrt(90)) < 1e-10 )) || err_exit 'c.len != sqrt(90)'
(( c.count == 2 )) || err_exit 'c.count != 2'
(( c.count == b.count )) || err_exit 'c.count != b.count'
c.count=0
Cube_t d=c
[[ $d == "$c" ]] || err_exit '$d != $c'
eval "Cube_t zzz=$c"
[[ $zzz == "$c" ]] || err_exit '$zzz != $c'
Cube_t zzz=c
[[ $zzz == "$c" ]] || err_exit '$zzz != $c without eval'
xxx=$(typeset -p c)
eval "${xxx/c=/ccc=}"
[[ $ccc == "$c" ]] || err_exit '$ccc != $c'
unset b c d zzz xxx ccc
done
for ((i=0; i < n; i++))
do
Cube_t cc
cc[2]=(x=2 y=3 name=two colors+=([table]=white) items+=(pencil) z=6)
[[ ${cc[0].x} == 8 ]] || err_exit 'cc[0].x !=8'
[[ ${cc[2].y} == 3 ]] || err_exit '${cc[2].y} != 3'
(( cc[2].y == 3 )) || err_exit '(( cc[2].y != 3))'
[[ ${cc[2].colors[table]} == white ]] || err_exit '${cc[2].colors[table]} != white'
[[ ${cc[2].items[2]} == pencil ]] || err_exit '${cc[2].items[2]} != pencil'
(( cc[2].len == 7 )) || err_exit '(( cc[2].len != 7 ))'
[[ $(cc[2].len) == 7 ]] || err_exit '$(cc[2].len) != 7 ))'
[[ ${cc[2].len} == 7 ]] || err_exit '${cc[2].len} != 7 ))'
(( cc[2].count == 2 )) || err_exit 'cc[2].count != 2'
unset cc[2].x cc[2].y cc[2].z
(( cc[2].len == cc[0].len )) || err_exit 'cc[2].len != cc[0].len'
(( cc[2].len == cc.len )) || err_exit 'cc[2].len != cc.len'
(( cc[2].count == 6 )) || err_exit 'cc[2].count != 6'
unset cc[2].name cc[2].colors cc[2].items
[[ $cc == "${cc[2]}" ]] || err_exit '$cc != ${cc[2]}'
cc.count=0
unset cc
Cube_t -A cc
cc[two]=(x=2 y=3 name=two colors+=([table]=white) items+=(pencil) z=6)
Cube_t cc[one]
[[ ${#cc[@]} == 2 ]] || err_exit '${#cc[@]} != 2'
[[ ${cc[two].y} == 3 ]] || err_exit '${cc[two].y} != 3'
(( cc[two].y == 3 )) || err_exit '(( cc[two].y != 3))'
[[ ${cc[two].colors[table]} == white ]] || err_exit '${cc[two].colors[table]} != white'
[[ ${cc[two].items[2]} == pencil ]] || err_exit '${cc[two].items[2]} != pencil'
(( cc[two].len == 7 )) || err_exit '(( cc[two].len != 7 ))'
[[ $(cc[two].len) == 7 ]] || err_exit '$(cc[two].len) != 7 ))'
[[ ${cc[two].len} == 7 ]] || err_exit '${cc[two].len} != 7 ))'
(( cc[two].count == 2 )) || err_exit 'cc[two].count != 2'
unset cc[two].x cc[two].y cc[two].z
(( cc[two].len == cc[one].len )) || err_exit 'cc[two].len != cc[one].len'
(( cc[two].count == 4 )) || err_exit 'cc[two].count != 4'
unset cc[two].name unset cc[two].colors cc[two].items
[[ ${cc[one]} == "${cc[two]}" ]] || err_exit '${cc[one]} != ${cc[two]}'
cc[two].count=0
unset cc
Cube_t cc=(
	[one]=
	[two]=(x=2 y=3 name=two colors+=([table]=white) z=6)
)
[[ ${#cc[@]} == 2 ]] || err_exit '${#cc[@]} != 2'
[[ ${cc[two].y} == 3 ]] || err_exit '${cc[two].y} != 3'
(( cc[two].y == 3 )) || err_exit '(( cc[two].y != 3))'
[[ ${cc[two].colors[table]} == white ]] || err_exit '${cc[two].colors[table]} != white'
(( cc[two].len == 7 )) || err_exit '(( cc[two].len != 7 ))'
[[ $(cc[two].len) == 7 ]] || err_exit '$(cc[two].len) != 7 ))'
[[ ${cc[two].len} == 7 ]] || err_exit '${cc[two].len} != 7 ))'
(( cc[two].count == 2 )) || err_exit 'cc[two].count != 2'
unset cc[two].x cc[two].y cc[two].z
(( cc[two].len == cc[one].len )) || err_exit 'cc[two].len != cc[one].len'
(( cc[two].count == 4 )) || err_exit 'cc[two].count != 4'
cc[three]=cc[two]
[[ ${cc[two]} == "${cc[three]}" ]] || err_exit "\${cc[two]}='${cc[two]}' != \${cc[three]}='${cc[three]}'"
[[ $cc[two] == "${cc[three]}" ]] || err_exit "\$cc[two]='${cc[two]}' != \${cc[three]}='${cc[three]}'"
exp=3
got=${#cc[@]}
[[ $got == $exp ]] || err_exit "\${#cc[@]} failed -- expected '$exp', got '$got'"
unset cc[two].name unset cc[two].colors
cc[two].count=0
unset cc
done

exit $((Errors<125?Errors:125))
