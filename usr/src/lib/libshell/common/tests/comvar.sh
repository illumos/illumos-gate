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
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

#test for compound variables
Command=${0##*/}
integer Errors=0
Point=(
	float x=1. y=0.
)
eval p="$Point"
if	(( (p.x*p.x + p.y*p.y) > 1.01 ))
then	err_exit 'compound variable not working'
fi
nameref foo=p
if	[[ ${foo.x} != ${Point.x} ]]
then	err_exit 'reference to compound object not working'
fi
unset foo
rec=(
	name='Joe Blow'
	born=(
		month=jan
		integer day=16
		year=1980
	)
)
eval newrec="$rec"
if	[[ ${newrec.name} != "${rec.name}" ]]
then	err_exit 'copying a compound object not working'
fi
if	(( newrec.born.day != 16 ))
then	err_exit 'copying integer field of  compound object not working'
fi
p_t=(
        integer z=0
        typeset -A tokens
)
unset x
typeset -A x
x=( [foo]=bar )
if	[[ ${x[@]} != bar ]]
then	err_exit 'compound assignemnt of associative arrays not working'
fi
unset -n foo x
unset foo x
foo=( x=3)
nameref x=foo
if	[[ ${!x.@} != foo.x ]]
then	err_exit 'name references not expanded on prefix matching'
fi
unset x
unset -n x
(
	x=()
	x.foo.bar=7
	[[ ${x.foo.bar} == 7 ]] || err_exit '[[ ${x.foo.bar} != 7 ]]'
	(( x.foo.bar == 7  ))|| err_exit '(( x.foo.bar != 7 ))'
	[[ ${x.foo} == *bar=7*  ]] || err_exit '[[ ${x.foo} != *bar=7* ]]'
)
foo=(integer x=3)
if	[[ ${foo} != *x=3* ]]
then	err_exit "compound variable with integer subvariable not working"
fi
$SHELL -c $'x=(foo=bar)\n[[ x == x ]]' 2> /dev/null || 
	err_exit '[[ ... ]] not working after compound assignment'
unset foo
[[ ${!foo.@} ]] && err_exit 'unset compound variable leaves subvariables'
suitable=(
  label="Table Viewer"
  langs="ksh"
  uselang=ksh
  launch=no
  groups="default"
  default=(
    label="Table Viewer Preferences"
    entrylist=" \
      vieworigin viewsize viewcolor viewfontname viewfontsize \
      showheader header showfooter footer showtitle title showlegends \
      class_td_lg1_style class_tr_tr1_style \
      class_th_th1_style class_td_td1_style \
      fields fieldorder \
    "
    entries=(
      vieworigin=(
        type=coord var=vieworigin val="0 0" label="Window Position"
      )
      viewsize=(
        type=coord var=viewsize val="400 400" label="Window Size"
      )
      viewcolor=(
        type=2colors var=viewcolor val="gray black"
        label="Window Colors"
      )
      viewfontname=(
        type=fontname var=viewfontname val="Times-Roman"
        label="Window Font Name"
      )
      viewfontsize=(
        type=fontsize var=viewfontsize val=14 label="Window Font Size"
      )

      showheader=(
        type=yesno var=showheader val=no label="Show Header"
      )
      header=(
        type=text var=header val="" label="Header"
      )

      showfooter=(
        type=yesno var=showfooter val=no label="Show Footer"
      )
      footer=(
        type=text var=footer val="" label="Footer"
      )

      showtitle=(
        type=yesno var=showtitle val=yes label="Show Title"
      )
      title=(
        type=text var=title val="SWIFTUI - Table View" label="Title"
      )

      showlegends=(
        type=yesno var=showlegends val=yes label="Show Legends"
      )

      class_td_lg1_style=(
        type=style var=class_td_lg1_style
        val="color: black; font-family: Times-Roman; font-size: 14pt"
        label="Legend 1 Style"
      )

      class_tr_tr1_style=(
        type=style var=class_tr_tr1_style val="background: black"
        label="Table Row 1 Style"
      )

      class_th_th1_style=(
        type=style var=class_th_th1_style
        val="color: black; font-family: Times-Roman; font-size: 14pt; text-align: left"
        label="Table Header 1 Style"
      )

      class_td_td1_style=(
        type=style var=class_td_td1_style
        val="color: black; font-family: Times-Roman; font-size: 14pt; text-align: left"
        label="Table Cell 1 Style"
      )

      fields=(
        type=text var=fields val= label="List of Fields"
      )
      fieldorder=(
        type=text var=fieldorder val= label="Order of Fields"
      )
    )
  )
)
[[ "${suitable}" == *entrylist=* ]] || err_exit 'compound variable expansion omitting fields'
foo=( bar=foo  barbar=bar)
[[ $foo == *bar=foo* ]] || err_exit 'no prefix elements in compound variable output'
function localvar
{
	typeset point=(typeset -i x=3 y=4)
	(( (point.x*point.x + point.y*point.y) == 25 )) || err_exit "local compound variable not working"
}
point=(integer x=6 y=8)
localvar
	(( (point.x*point.x + point.y*point.y) == 100 )) || err_exit "global compound variable not preserved"
[[ $($SHELL -c 'foo=();foo.[x]=(y z); print ${foo.x[@]}') == 'y z' ]] 2> /dev/null || err_exit 'foo=( [x]=(y z)  not working'
function staticvar
{
	if	[[ $1 ]] 
	then	print -r -- "$point"
		return
	fi
        typeset -S point=(typeset -i x=3 y=4)
        (( (point.x*point.x + point.y*point.y) == 25 )) || err_exit "local compound variable not working"
	point.y=5
	point.z=foobar
}
staticvar
        (( (point.x*point.x + point.y*point.y) == 100 )) || err_exit "global compound variable not preserved"
[[ $(staticvar x) == $'(\n\ttypeset -i x=3\n\ttypeset -i y=5\n\tz=foobar\n)' ]] || err_exit 'static variables in function not working'
integer x=3
( typeset -S x=+++)2> /dev/null  || err_exit "typeset -S doesn't unset first"

unset z
( [[ ${z.foo.bar:-abc} == abc ]] 2> /dev/null) || err_exit ':- not working with compound variables'
stack=()
typeset -a stack.items=([0]=foo [1]=bar)
[[ ${stack.items[0]} == foo ]] || err_exit 'typeset -a variable not expanding correctly'
$SHELL -c 'typeset -a info=( [1]=( passwd=( since=2005-07-20) ))'  || err_exit 'problem with embedded index array in compound variable'
x=(foo=([1]=(y=([2]=(z=4)))))
[[ $x == *'.y'=* ]] && err_exit 'expansion with bogus leading . in name'
unset z
z=1
function foo
{
	z=3
	[[ ${a.z} == 3 ]] && err_exit "\${a.z} should not be 3"
	print hi
}
a=( b=$(foo) )
[[ ${a.z} == 3 ]] &&  err_exit 'a.z should not be set to 3'
function a.b.get
{
	.sh.value=foo
}
{ b=( b1=${a.b} ) ;} 2> /dev/null
[[ ${b.b1} == foo ]] || err_exit '${b.b1} should be foo'
function dcl1
{
     eval 'a=1
     function a.set
     { print ${.sh.name}=${.sh.value}; }'
}
function dcl2
{
     eval 'b=(typeset x=0; typeset y=0 )
     function b.x.set
     { print ${.sh.name}=${.sh.value}; }'
}
dcl1
[[ ${ a=123;} == 'a=123' ]] || err_exit 'should be a=123'
dcl2
[[ ${ b.x=456;} == 'b.x=456' ]] || err_exit 'should be b.x=456'
eval 'b=(typeset x=0; typeset y=0 )
function b.x.set
{ print ${.sh.name}=${.sh.value}; }' > /dev/null
[[ ${ b.x=789;} == 'b.x=789' ]] || err_exit 'should be b.x=789'
unset a b
function func
{
	typeset X
	X=( bar=2 )
}

X=( foo=1 )
func
[[ $X == $'(\n\tfoo=1\n)' ]] || err_exit 'scoping problem with compound variables'
unset foo
typeset -A foo=([a]=aa;[b]=bb;[c]=cc)
[[ ${foo[c]} == cc ]] || err_exit 'associative array assignment with; not working'
[[ $({ $SHELL -c 'x=(); typeset -a x.foo; x.foo=bar; print -r -- "$x"' ;} 2> /dev/null) == $'(\n\ttypeset -a foo=bar\n)' ]] || err_exit 'indexed array in compound variable with only element 0 defined fails'
unset foo
foo=(typeset -a bar)
[[ $foo  == *'typeset -a bar'* ]] || err_exit 'array attribute -a not preserved in compound variable'
unset s
typeset -A s=( [foo]=(y=2 z=3) [bar]=(y=4 z=5))
[[ ${s[@]} == *z=*z=* ]] || err_exit 'missing elements in compound associative array'
unset nodes
typeset -A nodes
nodes[0]+=( integer x=5)
[[ ${nodes[0].x} == 5 ]] || err_exit '${nodes[0].x} should be 5'
unset foo
typeset -C foo
foo.bar=abc
[[ $foo == $'(\n\tbar=abc\n)' ]] || err_exit 'typeset -C not working for foo'
typeset -C foo=(bar=def)
[[ $foo == $'(\n\tbar=def\n)' ]] || err_exit 'typeset -C not working when initialized'
foo=(
	hello=ok
	yes=( bam=2 yes=4)
	typeset -A array=([one]=one [two]=2)
	last=me
)
eval foo2="$foo"
foo2.hello=notok foo2.yes.yex=no foo2.extra=yes.
typeset -C bar bam 
{
	read -Cu3 bar
	read -Cu3 bam
	read -ru3
} 3<<- ++++
	"$foo"
	"$foo2"
	last line
++++
[[ $? == 0 ]] || err_exit ' read -C failed'
[[ $bar == "$foo" ]] || err_exit '$foo != $bar'
[[ $bam == "$foo2" ]] || err_exit '$foo2 != $bmr'
[[ $REPLY == 'last line' ]] || err_exit "\$REPLY=$REPLY should be 'last line"
typeset x=( typeset -a foo=( [1][3]=hello [9][2]="world" ) )
eval y="(typeset -a foo=$(printf "%B\n" x.foo) )"
[[ $x == "$y" ]] || err_exit '$x.foo != $y.foo with %B'
eval y="(typeset -a foo=$(printf "%#B\n" x.foo) )"
[[ $x == "$y" ]] || err_exit '$x.foo != $y.foo with %#B'
eval y="$(printf "%B\n" x)"
[[ $x == "$y" ]] || err_exit '$x != $y with %B'
eval y="$(printf "%#B\n" x)"
[[ $x == "$y" ]] || err_exit '$x != $y with %#B'
y=$(set | grep ^x=) 2> /dev/null
eval "${y/#x/y}"
[[ $x == "$y" ]] || err_exit '$x != $y with set | grep'
unset x y z
x=( float x=0 y=1; z=([foo]=abc [bar]=def))
typeset -C y=x
[[ $x == "$y" ]] || err_exit '$x != $y with typeset -C'
unset y
y=()
y=x
[[ $x == "$y" ]] || err_exit '$x != $y when x=y and x and y are -C '
function foobar
{
	typeset -C z
	z=x
	[[ $x == "$z" ]] || err_exit '$x != $z when x=z and x and z are -C '
	y=z
}
[[ $x == "$y" ]] || err_exit '$x != $y when x=y -C copied in a function '
z=(foo=abc)
y+=z
[[ $y == *foo=abc* ]] || err_exit 'z not appended to y'
unset y.foo
[[ $x == "$y" ]] || err_exit '$x != $y when y.foo deleted'
unset x y
x=( foo=(z=abc d=ghi) bar=abc; typeset -A r=([x]=3  [y]=4))
unset x
x=()
[[ $x == $'(\n)' ]] || err_exit 'unset compound variable is not empty'

unset z
z=()
z.foo=( [one]=hello [two]=(x=3 y=4) [three]=hi)
z.bar[0]=hello
z.bar[2]=world
z.bar[1]=(x=4 y=5)
exp='(
	typeset -a bar=(
		[0]=hello
		[2]=world
		[1]=(
			x=4
			y=5
		)
	)
	typeset -A foo=(
		[one]=hello
		[three]=hi
		[two]=(
			x=3
			y=4
		)
	)
)'
got=$z
[[ $got == "$exp" ]] || {
	exp=$(printf %q "$exp")
	got=$(printf %q "$got")
	err_exit "compound indexed array pretty print failed -- expected $exp, got $got"
}

typeset -A record
record[a]=(
	typeset -a x=(
		[1]=(
			X=1
		)
	)
)
exp=$'(\n\ttypeset -a x=(\n\t\t[1]=(\n\t\t\tX=1\n\t\t)\n\t)\n)'
got=${record[a]}
[[ $got == "$exp" ]] || {
	exp=$(printf %q "$exp")
	got=$(printf %q "$got")
	err_exit "compound indexed array pretty print failed -- expected $exp, got $got"
}

unset r
r=(
	typeset -a x=(
		[1]=(
			X=1
		)
	)
)
exp=$'(\n\ttypeset -a x=(\n\t\t[1]=(\n\t\t\tX=1\n\t\t)\n\t)\n)'
got=$r
[[ $got == "$exp" ]] || {
	exp=$(printf %q "$exp")
	got=$(printf %q "$got")
	err_exit "compound indexed array pretty print failed -- expected $exp, got $got"
}

# array of compund variables
typeset -C data=(
        typeset -a samples
)
data.samples+=(
	type1="greeting1"
	timestamp1="now1"
	command1="grrrr1"
)
data.samples+=(
	type2="greeting2"
	timestamp2="now2"
	command2="grrrr2"
)

[[ $data == %(()) ]] || err_exit "unbalanced parenthesis with compound variable containing array of compound variables" 
exit $((Errors))
