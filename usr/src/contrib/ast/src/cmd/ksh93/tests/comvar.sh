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
typeset -C  -A hello=( [foo]=bar)
[[ $(typeset -p hello) == 'typeset -C -A hello=([foo]=bar)' ]] || err_exit 'typeset -A -C with intial assignment not working'
# this caused a core dump before ksh93t+
[[ $($SHELL -c 'foo=(x=3 y=4);function bar { typeset z=4;: $z;};bar;print ${!foo.@}') == 'foo.x foo.y' ]] 2> /dev/null || err_exit '${!foo.@} after function not working'

function foo
{
	typeset tmp
	read -C tmp
	read -C tmp
}
foo 2> /dev/null <<-  \EOF ||  err_exit 'deleting compound variable in function failed'
	(
		typeset -A myarray3=(
			[a]=( foo=bar)
			[b]=( foo=bar)
			[c d]=( foo=bar)
			[e]=( foo=bar)
			[f]=( foo=bar)
			[g]=( foo=bar)
			[h]=( foo=bar)
			[i]=( foo=bar)
			[j]=( foo=bar)
		)
	)
	hello
EOF

typeset -C -a mica01
mica01[4]=( a_string="foo bar" )
typeset -C more_content=(
	some_stuff="hello"
)
mica01[4]+=more_content
expected=$'typeset -C -a mica01=([4]=(a_string=\'foo bar\';some_stuff=hello))'
[[ $(typeset -p mica01) == "$expected" ]] || err_exit 'appened to indexed array compound variable not working'

unset x
compound x=( integer x ; )
[[ ! -v x.x ]] && err_exit 'x.x should be set'
expected=$'(\n\ttypeset -l -i x=0\n)'
[[ $(print -v x) == "$expected" ]] || err_exit "'print -v x' should be $expected"

typeset -C -A hello19=(
	[19]=(
		one="xone 19"
		two="xtwo 19"
	)
	[23]=(
		one="xone 23"
		two="xtwo 23"
	)
)
expected="typeset -C -A hello19=([19]=(one='xone 19';two='xtwo 19') [23]=(one='xone 23';two='xtwo 23'))"
[[ $(typeset -p hello19) == "$expected" ]] || print -u2 'typeset -p hello19 incorrect'
expected=$'(\n\tone=\'xone 19\'\n\ttwo=\'xtwo 19\'\n) (\n\tone=\'xone 23\'\n\ttwo=\'xtwo 23\'\n)'
[[ ${hello19[@]} == "$expected" ]] || print -u2 '${hello19[@]} incorrect'

typeset -C -A foo1=( abc="alphabet" ) foo2=( abc="alphabet" )
function add_one
{
	nameref left_op=$1
	typeset -C info
	info.hello="world"
	nameref x=info
	left_op+=x
}
nameref node1="foo1[1234]"
add_one "node1"
add_one "foo2[1234]"
[[ "${foo1[1234]}" == "${foo2[1234]}" ]] || err_exit "test failed\n$(diff -u <( print -r -- "${foo1[1234]}") <(print -r -- "${foo2[1234]}"))."

typeset -C tree
function f1
{
        nameref tr=$1
        typeset -A tr.subtree
        typeset -C node
        node.one="hello"
        node.two="world"
        
        # move local note into the array
        typeset -m tr.subtree["a_node"]=node
}
f1 tree
expected=$'(\n\ttypeset -A subtree=(\n\t\t[a_node]=(\n\t\t\tone=hello\n\t\t\ttwo=world\n\t\t)\n\t)\n)'
[[ $tree == "$expected" ]] ||  err_exit 'move of compound local variable to global variable not working'

typeset -C -A array
float array[12].amount=2.9 
expected='typeset -C -A array=([12]=(typeset -l -E amount=2.9))'
[[ $(typeset -p array) == "$expected" ]] || err_exit 'typeset with compound  variable with compound variable array not working'

typeset -T foo_t=(
        function diff
        {
		print 1.0
                return 0
        }
)
foo_t sw
compound output=(
        integer one=1
        float mydiff=sw.diff
        float end=.314
)
[[ $output == *end=* ]] ||  err_exit "The field 'name' end is missing"

compound cpv1=( integer f=2 ) 
compound x=(
	integer a=1
	compound b=cpv1 
) 
[[ $x == *f=2* ]] ||  err_exit "The field b containg 'f=2' is missing"

unset x
compound x=(
        compound -a nodes=(
                 [4]=( )
        )
) 
expected='typeset -C x=(typeset -C -a nodes=([4]=());)'
[[ $(typeset -p x) == "$expected" ]] || err_exit 'typeset -p with nested compound index array not working'

unset v
compound v=(
	integer -A ar=(
		[aa]=4 [bb]=9
	) 
) 
expected='typeset -C v=(typeset -A -l -i ar=([aa]=4 [bb]=9);)'
[[ $(typeset -p v) == "$expected" ]] || err_exit 'attributes for associative arrays embedded in compound variables not working'

unset x
compound -a x
x[1]=( a=1 b=2 )
[[ $(print -v x[1]) == "${x[1]}" ]] || err_exit  'print -v x[1] not working for index array of compound variables'

unset x
z='typeset -a x=(hello (x=12;y=5) world)'
{ eval "$z" ;} 2> /dev/null
[[ $(typeset -p x) == "$z" ]] || err_exit "compound assignment '$z' not working"

expected='typeset -C -A l=([4]=(typeset -a ar=(1 2 3);b=1))'
typeset -A -C l
printf "( typeset -a ar=( 1\n2\n3\n) b=1 )\n" | read -C l[4] 
[[ $(typeset -p l) == "$expected" ]] ||  err_exit 'read -C for associative array of compound variables not working'

unset x
compound x=( z="a=b c")
exp=$'typeset -C x=(z=a\\=\'b c\')'
got=$(typeset -p x)
[[ $got == "$exp" ]] || err_exit "typeset -p failed -- expected '$exp', got '$got'"

x=(typeset -C -a y;float z=2)
got=$(print -C x)
expected='(typeset -C -a y;typeset -l -E z=2)'
[[ $expected == "$got" ]] || err_exit "print -C x exects '$expected' got '$got'"

unset vx vy
compound vx=(
	compound -a va=(
		[3][17]=(
			integer -A ar=( [aa]=4 [bb]=9 )
		)
	)
)
eval "vy=$(print -C vx)"
[[ $vx == "$vy" ]] || err_exit 'print -C with multi-dimensional array not working'
eval "vy=$(print -v vx)"
[[ $vx == "$vy" ]] || err_exit 'print -v with multi-dimensional array not working'

unset x
typeset -C -A x=( [0]=(a=1) [1]=(b=2) )
expected=$'(\n\t[0]=(\n\t\ta=1\n\t)\n\t[1]=(\n\t\tb=2\n\t)\n)'
[[ $(print -v x) == "$expected" ]] || err_exit 'print -v not formatting correctly'

compound -a x=( [0]=(a=1) [1]=(b=2) )
typeset -m "z=x[1]"
[[ $(typeset -p z 2>/dev/null) == 'typeset -C z=(b=2)' ]] || err_exit 'typeset -m not working with commpound -a variable'

unset x z
compound -A x=( [0]=(a=1) [1]=(b=2) )
typeset -m "z=x[1]"
[[ $(typeset -p z 2>/dev/null) == 'typeset -C z=(b=2)' ]] || err_exit 'typeset -m not working with commpound -a variable'
typeset -m "x[1]=x[0]"
typeset -m "x[0]=z"
exp='([0]=(b=2) [1]=(a=1))'
[[ $(print -C x) == "$exp" ]] || err_exit 'typeset -m not working for associative arrays'

unset z r
z=(a b c)
r=(x=3 y=4)
typeset -m z[1]=r
exp='typeset -a z=(a (x=3;y=4) c)'
[[ $(typeset -p z) == "$exp" ]] || err_exit 'moving compound variable into indexed array fails'

unset c
compound c
compound -a c.a=( [1]=( aa=1 ) )
compound -a c.b=( [2]=( bb=2 ) )
typeset -m "c.b[9]=c.a[1]"
exp='typeset -C c=(typeset -C -a a;typeset -C -a b=( [2]=(bb=2;)[9]=(aa=1));)'
[[ $(typeset -p c) == "$exp" ]] || err_exit 'moving compound indexed array element to another index fails'

unset c
compound c
compound -a c.a=( [1]=( aa=1 ) )
compound -A c.b=( [2]=( bb=2 ) )
typeset -m "c.b[9]=c.a[1]"
exp='typeset -C c=(typeset -C -a a;typeset -C -A b=( [2]=(bb=2;)[9]=(aa=1));)'
[[ $(typeset -p c) == "$exp" ]] || err_exit 'moving compound indexed array element to a compound associative array element fails'

zzz=(
	foo=(
		bar=4
	)
)
[[ $(set | grep "^zzz\.") ]] && err_exit 'set displays compound variables incorrectly'

typeset -A stats
stats[1]=(a=1 b=2)
stats[2]=(a=1 b=2)
stats[1]=(c=3 d=4)
(( ${#stats[@]} == 2 )) || err_exit "stats[1] should contain 2 element not ${#stats[@]}"

integer i=1
foo[i++]=(x=3 y=4)
[[ ${foo[1].x} == 3 ]] || err_exit "\${foo[1].x} should be 3"
[[ ${foo[1].y} == 4 ]] || err_exit "\${foo[1].y} should be 4"

# ${!x.} caused core dump in ks93u and earlier
{ $SHELL -c 'compound x=(y=1); : ${!x.}' ; ((!$?));} || err_exit '${!x.} not working'

$SHELL -c 'typeset -A a=([b]=c)' 2> /dev/null || err_exit 'typeset -A a=([b]=c) fails'

compound -a a
compound c=( name="container1" )
a[4]=c 
[[ ${a[4]} == $'(\n\tname=container1\n)' ]] || err_exit 'assignment of compound variable to compound array element not working'

unset c
compound  c
compound  -a c.board
for ((i=2; i < 4; i++))
do	c.board[1][$i]=(foo=bar)
done
exp=$'(\n\ttypeset -C -a board=(\n\t\t[1]=(\n\t\t\t[2]=(\n\t\t\t\tfoo=bar\n\t\t\t)\n\t\t\t[3]=(\n\t\t\t\tfoo=bar\n\t\t\t)\n\t\t)\n\t)\n)'
[[ "$(print -v c)" == "$exp" ]] || err_exit 'compound variable assignment to two dimensional array not working'

unset zz
zz=()
zz.[foo]=abc
zz.[2]=def
exp='typeset -C zz=([2]=def;foo=abc)'
[[ $(typeset -p zz) == "$exp" ]] || err_exit 'expansion of compound variables with non-identifiers not working'
(
	typeset -i zz.[3]=123
	exec 2>& 3-
	exp='typeset -C zz=([2]=def;typeset -i [3]=123;foo=abc)'
	[[ $(typeset -p zz) == "$exp" ]] || err_exit 'expansion of compound variables with non-identifiers not working in subshells'
)  3>&2 2> /dev/null || err_exit 'syntax errors expansion of compound variables with non-identifiers'

unset xx
xx=(foo=bar)
xx=()
[[ $xx == $'(\n)' ]] || err_exit 'xx=() not unsetting previous value'

exit $((Errors<125?Errors:125))
