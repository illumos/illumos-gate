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

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

trap '' FPE # NOTE: osf.alpha requires this (no ieee math)

integer x=1 y=2 z=3
if	(( 2+2 != 4 ))
then	err_exit 2+2!=4
fi
if	((x+y!=z))
then	err_exit x+y!=z
fi
if	(($x+$y!=$z))
then	err_exit $x+$y!=$z
fi
if	(((x|y)!=z))
then	err_exit "(x|y)!=z"
fi
if	((y >= z))
then	err_exit "y>=z"
fi
if	((y+3 != z+2))
then	err_exit "y+3!=z+2"
fi
if	((y<<2 != 1<<3))
then	err_exit "y<<2!=1<<3"
fi
if	((133%10 != 3))
then	err_exit "133%10!=3"
	if	(( 2.5 != 2.5 ))
	then	err_exit 2.5!=2.5
	fi
fi
d=0
((d || 1)) || err_exit 'd=0; ((d||1))'
if	(( d++!=0))
then	err_exit "d++!=0"
fi
if	(( --d!=0))
then	err_exit "--d!=0"
fi
if	(( (d++,6)!=6 && d!=1))
then	err_exit '(d++,6)!=6 && d!=1'
fi
d=0
if	(( (1?2+1:3*4+d++)!=3 || d!=0))
then	err_exit '(1?2+1:3*4+d++) !=3'
fi
for	((i=0; i < 20; i++))
do	:
done
if	(( i != 20))
then	err_exit 'for (( expr)) failed'
fi
for	((i=0; i < 20; i++)); do	: ; done
if	(( i != 20))
then	err_exit 'for (( expr));... failed'
fi
for	((i=0; i < 20; i++)) do	: ; done
if	(( i != 20))
then	err_exit 'for (( expr))... failed'
fi
if	(( (i?0:1) ))
then	err_exit '(( (i?0:1) )) failed'
fi
if	(( (1 || 1 && 0) != 1 ))
then	err_exit '( (1 || 1 && 0) != 1) failed'
fi
if	(( (_=1)+(_x=0)-_ ))
then	err_exit '(_=1)+(_x=0)-_ failed'
fi
if	((  (3^6) != 5))
then	err_exit '((3^6) != 5) failed'
fi
integer x=1
if	(( (x=-x) != -1 ))
then	err_exit '(x=-x) != -1 failed'
fi
i=2
if	(( 1$(($i))3 != 123 ))
then	err_exit ' 1$(($i))3 failed'
fi
((pi=4*atan(1.)))
point=(
	float x
	float y
)
(( point.x = cos(pi/6), point.y = sin(pi/6) ))
if	(( point.x*point.x + point.y*point.y > 1.01 ))
then	err_exit 'cos*cos +sin*sin > 1.01'
fi
if	(( point.x*point.x + point.y*point.y < .99 ))
then	err_exit 'cos*cos +sin*sin < .99'
fi
if [[ $((y=x=1.5)) != 1 ]]
then	err_exit 'typecast not working in arithmetic evaluation'
fi
typeset -E x=1.5
( ((x++))  ) 2>/dev/null
if [[ $? == 0 ]]
then	err_exit 'postincrement of floating point allowed'
fi
( ((++x))  ) 2>/dev/null
if [[ $? == 0 ]]
then	err_exit 'preincrement of floating point allowed'
fi
x=1.5
( ((x%1.1))  ) 2>/dev/null
if [[ $? == 0 ]]
then	err_exit 'floating point allowed with % operator'
fi
x=.125
if	[[ $(( 4 * x/2 )) != 0.25 ]]
then	err_exit '(( 4 * x/2 )) is not 0.25, with x=.125'
fi
if	[[ $(( pow(2,3) )) != 8 ]]
then	err_exit '$(( pow(2,3) )) != 8'
fi
( [[ $(( pow(2,(3)) )) == 8 ]] ) 2> /dev/null
if	(( $? ))
then	err_exit '$(( pow(2,(3)) )) != 8'
fi
unset x
integer x=1; integer x=1
if	[[ $x != 1 ]]
then	err_exit 'two consecutive integer x=1 not working'
fi
unset z
{ z=$(typeset -RZ2 z2; (( z2 = 8 )); print $z2) ;} 2>/dev/null
if [[ $z != "08" ]]
then	err_exit "typeset -RZ2 leading 0 decimal not working [z=$z]"
fi
{ z=$(typeset -RZ3 z3; (( z3 = 8 )); print $z3) ;} 2>/dev/null
if [[ $z != "008" ]]
then	err_exit "typeset -RZ3 leading 0 decimal not working [z=$z]"
fi
unset z
typeset -Z3 z=010
(( z=z+1))
if	[[ $z != 011 ]]
then	err_exit "leading 0's in -Z not treated as decimal"
fi
unset x
integer x=0
if	[[ $((x+=1)) != 1  ]] || ((x!=1))
then	err_exit "+= not working"
	x=1
fi
x=1
if	[[ $((x*=5)) != 5  ]] || ((x!=5))
then	err_exit "*= not working"
	x=5
fi
if	[[ $((x%=4)) != 1  ]] || ((x!=1))
then	err_exit "%= not working"
	x=1
fi
if	[[ $((x|=6)) != 7  ]] || ((x!=7))
then	err_exit "|= not working"
	x=7
fi
if	[[ $((x&=5)) != 5  ]] || ((x!=5))
then	err_exit "&= not working"
	x=5
fi
function newscope
{
	float x=1.5
	(( x += 1 ))
	print -r -- $x
}
if	[[ $(newscope) != 2.5 ]]
then	err_exit "arithmetic using wrong scope"
fi
unset x
integer y[3]=9 y[4]=2 i=3
(( x = y[3] + y[4] ))
if	[[ $x != 11 ]]
then	err_exit "constant index array arithmetic failure"
fi
(( x = $empty y[3] + y[4] ))
if	[[ $x != 11 ]]
then	err_exit "empty constant index array arithmetic failure"
fi
(( x = y[i] + y[i+1] ))
if	[[ $x != 11 ]]
then	err_exit "variable subscript index array arithmetic failure"
fi
integer a[5]=3 a[2]=4
(( x = y[a[5]] + y[a[2]] ))
if	[[ $x != 11 ]]
then	err_exit "nested subscript index array arithmetic failure"
fi
unset y
typeset -Ai y
y[three]=9 y[four]=2
three=four
four=three
(( x = y[three] + y[four] ))
if	[[ $x != 11 ]]
then	err_exit "constant associative array arithmetic failure"
fi
(( x = y[$three] + y[$four] ))
if	[[ $x != 11 ]]
then	err_exit "variable subscript associative array arithmetic failure"
fi
$SHELL -nc '((a = 1))' 2> /dev/null || err_exit "sh -n fails with arithmetic"
$SHELL -nc '((a.b++))' 2> /dev/null || err_exit "sh -n fails with arithmetic2"
unset z
float z=7.5
if	{ (( z%2 != 1));} 2> /dev/null
then	err_exit '% not working on floating point'
fi
chr=(a ' ' '=' '\r' '\n' '\\' '\"' '$' "\\'" '[' ']' '(' ')' '<' '\xab' '\040' '`' '{' '}' '*' '\E')
if	(('a' == 97))
then	val=(97 32  61 13 10 92 34 36 39 91 93 40 41 60 171 32 96 123 125 42 27)
else	val=(129 64 126 13 21 224 127 91 125 173 189 77 93 76 171 32 121 192 208 92 39 21)
fi
q=0
for ((i=0; i < ${#chr[@]}; i++))
do	if	(( '${chr[i]}' != ${val[i]} ))
	then	err_exit "(( '${chr[i]}'  !=  ${val[i]} ))"
	fi
	if	[[ $(( '${chr[i]}' )) != ${val[i]} ]]
	then	err_exit "(( '${chr[i]}' )) !=  ${val[i]}"
	fi
	if	[[ $(( L'${chr[i]}' )) != ${val[i]} ]]
	then	err_exit "(( '${chr[i]}' )) !=  ${val[i]}"
	fi
	if	eval '((' "'${chr[i]}'" != ${val[i]} '))'
	then	err_exit "eval (( '${chr[i]}'  !=  ${val[i]} ))"
	fi
	if	eval '((' "'${chr[i]}'" != ${val[i]} ' + $q ))'
	then	err_exit "eval (( '${chr[i]}'  !=  ${val[i]} ))"
	fi
done
unset x
typeset -ui x=4294967293
[[ $x != 4294967293 ]]  && err_exit "unsigned integers not working"
x=32767
x=x+1
[[ $x != 32768 ]]  && err_exit "unsigned integer addition not working"
unset x
float x=99999999999999999999999999
if	(( x < 1e20 ))
then	err_exit 'large integer constants not working'
fi
unset x  y
function foobar
{
	nameref x=$1
	(( x +=1 ))
	print $x
}
x=0 y=4
if	[[ $(foobar y) != 5 ]]
then	err_exit 'name references in arithmetic statements in functions broken'
fi
if	(( 2**3 != pow(2,3) ))
then	err_exit '2**3 not working'
fi
if	(( 2**3*2 != pow(2,3)*2 ))
then	err_exit '2**3*2 not working'
fi
if	(( 4**3**2 != pow(4,pow(3,2)) ))
then	err_exit '4**3**2 not working'
fi
if	(( (4**3)**2 != pow(pow(4,3),2) ))
then	err_exit '(4**3)**2 not working'
fi
typeset -Z3 x=11
typeset -i x
if	(( x != 11 ))
then	err_exit '-Z3 not treated as decimal'
fi
unset x
typeset -ui x=-1
(( x >= 0 )) || err_exit 'unsigned integer not working'
(( $x >= 0 )) || err_exit 'unsigned integer not working as $x'
unset x
typeset -ui42 x=50
if	[[ $x != 42#18 ]]
then	err_exit 'display of unsigned integers in non-decimal bases wrong'
fi
$SHELL -c 'i=0;(( ofiles[i] != -1 && (ofiles[i] < mins || mins == -1) ));exit 0' 2> /dev/null || err_exit 'lexical error with arithemtic expression'
$SHELL -c '(( +1 == 1))' 2> /dev/null || err_exit 'unary + not working'
typeset -E20 val=123.01234567890
[[ $val == 123.0123456789 ]] || err_exit "rounding error val=$val"
if	[[ $(print x$((10))=foo) != x10=foo ]]
then	err_exit 'parsing error with x$((10))=foo'
fi
$SHELL -c 'typeset x$((10))=foo' 2> /dev/null || err_exit 'typeset x$((10)) parse error'
unset x
x=$(( exp(log(2.0)) ))
(( x > 1.999 && x < 2.001 )) || err_exit 'composite functions not working'
unset x y n
typeset -Z8 x=0 y=0
integer n
for	(( n=0; n < 20; n++ ))
do	let "x = $x+1"
	(( y = $y+1 ))
done
(( x == n ))  || err_exit 'let with zero filled fields not working'
(( y == n ))  || err_exit '((...)) with zero filled fields not working'
typeset -RZ3 x=10
[[ $(($x)) == 10 && $((1$x)) == 1010 ]] || err_exit 'zero filled fields not preserving leading zeros'
unset y
[[ $(let y=$x;print $y) == 10 && $(let y=1$x;print $y) == 1010 ]] || err_exit 'zero filled fields not preserving leading zeros with let'
unset i ip ipx
typeset -i hex=( 172 30 18 1)
typeset -iu ip=0 ipx=0
integer i
for	((i=0; i < 4; i++))
do	(( ip =  (ip<<8) | hex[i]))
done
for ((i=0; i < 4; i++))
do	(( ipx = ip % 256 ))
	(( ip /= 256 ))
	(( ipx != hex[3-i] )) && err_exit "hex digit $((3-i)) not correct"
done
unset x
x=010
(( x == 8 )) || err_exit 'leading zeros not treated as octal arithmetic'
(( $x == 8 )) || err_exit 'leading zeros not treated as octal arithmetic with $x'
unset x
typeset -Z x=010
(( x == 10 )) || err_exit 'leading zeros not ignored for arithmetic'
(( $x == 10 )) || err_exit 'leading zeros not ignored for arithmetic with $x'
typeset -i i=x
(( i == 10 )) || err_exit 'leading zeros not ignored for arithmetic assignment'
(( ${x:0:1} == 0 )) || err_exit 'leading zero should not be stripped for x:a:b'
c010=3
(( c$x  == 3 )) || err_exit 'leading zero with variable should not be stripped'
[[ $( ($SHELL -c '((++1))' 2>&1)2>/dev/null ) == *lvalue* ]] || err_exit "((++1)) not generating error message"
i=2
(( "22" == 22 )) || err_exit "double quoted constants fail"
(( "2$i" == 22 )) || err_exit "double quoted variables fail"
(( "18+$i+2" == 22 )) || err_exit "double quoted expressions fail"
# 04-04-28 bug fix
unset i; typeset -i i=01-2
(( i == -1 )) || err_exit "01-2 is not -1"

cat > $tmp/script <<-\!
tests=$*
typeset -A blop
function blop.get
{
	.sh.value=777
}
function mkobj
{
	nameref obj=$1
	obj=()
	[[ $tests == *1* ]] && {
		(( obj.foo = 1 ))
		(( obj.bar = 2 ))
		(( obj.baz = obj.foo + obj.bar ))	# ok
		echo $obj
	}
	[[ $tests == *2* ]] && {
		(( obj.faz = faz = obj.foo + obj.bar ))	# ok
		echo $obj
	}
	[[ $tests == *3* ]] && {
		# case 3, 'active' variable involved, w/ intermediate variable
		(( obj.foz = foz = ${blop[1]} ))	# coredump
		echo $obj
	}
	[[ $tests == *4* ]] && {
		# case 4, 'active' variable, in two steps
		(( foz = ${blop[1]} ))	# ok
		(( obj.foz = foz ))		# ok
		echo $obj
	}
	[[ $tests == *5* ]] && {
		# case 5, 'active' variable involved, w/o intermediate variable
		(( obj.fuz = ${blop[1]} ))	# coredump
		echo $obj
	}
	[[ $tests == *6* ]] && {
		echo $(( obj.baz = obj.foo + obj.bar ))	# coredump
	}
	[[ $tests == *7* ]] && {
		echo $(( obj.foo + obj.bar ))	# coredump
	}
}
mkobj bla
!
chmod +x $tmp/script
[[ $($tmp/script 1) != '( bar=2 baz=3 foo=1 )' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
[[ $($tmp/script 2) != '( faz=0 )' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
[[ $($tmp/script 3) != '( foz=777 )' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
[[ $($tmp/script 4) != '( foz=777 )' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
[[ $($tmp/script 5) != '( fuz=777 )' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
[[ $($tmp/script 6) != '0' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
[[ $($tmp/script 7) != '0' ]] 2>/dev/null && err_exit 'compound var arithmetic failed'
unset foo
typeset -F1 foo=123456789.19
[[ $foo == 123456789.2 ]] || err_exit 'typeset -F1 not working correctly'

# divide by zero

for expr in '1/(1/2)' '8%(1/2)' '8%(1.0/2)'
do	[[ $( ( $SHELL -c "( (($expr)) )  || print ok" ) 2>/dev/null ) == ok ]] || err_exit "divide by zero not trapped: $expr"
done

for expr in '1/(1.0/2)' '1/(1/2.0)'
do	[[ $( ( $SHELL -c "( print -r -- \$(($expr)) )" ) 2>/dev/null ) == 2 ]] || err_exit "invalid value for: $expr"
done
[[ $((5||0)) == 1 ]] || err_exit '$((5||0))'" == $((5||0)) should be 1"
$SHELL -c 'integer x=3 y=2; (( (y += x += 2) == 7  && x==5))' 2> /dev/null || err_exit '((y += x += 2)) not working'
$SHELL -c 'b=0; [[ $((b?a=1:b=9)) == 9 ]]' 2> /dev/null || err_exit 'b?a=1:b=9 not working'
unset x
(( x = 4*atan(1.0) ))
[[ $x == "$((x))" ]] || err_exit  '$x !- $((x)) when x is pi'
$SHELL -c  "[[  ${x//./} == {14,100}(\d) ]]" 2> /dev/null || err_exit 'pi has less than 14 significant places'
if	(( Inf+1 == Inf ))
then	set \
		Inf		inf	\
		-Inf		-inf	\
		Nan		nan	\
		-Nan		-nan	\
		1.0/0.0		inf
	while	(( $# >= 2 ))
	do	x=$(printf "%g\n" $(($1)))
		[[ $x == $2 ]] || err_exit "printf '%g\\n' \$(($1)) failed -- expected $2, got $x"
		x=$(printf "%g\n" $1)
		[[ $x == $2 ]] || err_exit "printf '%g\\n' $1 failed -- expected $2, got $x"
		x=$(printf -- $(($1)))
		[[ $x == $2 ]] || err_exit "print -- \$(($1)) failed -- expected $2, got $x"
		shift 2
	done
	(( 1.0/0.0 == Inf )) || err_exit '1.0/0.0 != Inf'
	[[ $(print -- $((0.0/0.0))) == ?(-)nan ]] || err_exit '0.0/0.0 != NaN'
	(( Inf*Inf == Inf )) || err_exit 'Inf*Inf != Inf'
	(( NaN != NaN )) || err_exit 'NaN == NaN'
	(( -5*Inf == -Inf )) || err_exit '-5*Inf != -Inf'
	[[ $(print -- $((sqrt(-1.0)))) == ?(-)nan ]]|| err_exit 'sqrt(-1.0) != NaN'
	(( pow(1.0,Inf) == 1.0 )) || err_exit 'pow(1.0,Inf) != 1.0'
	(( pow(Inf,0.0) == 1.0 )) || err_exit 'pow(Inf,0.0) != 1.0'
	[[ $(print -- $((NaN/Inf))) == ?(-)nan ]] || err_exit 'NaN/Inf != NaN'
	(( 4.0/Inf == 0.0 )) || err_exit '4.0/Inf != 0.0'
else	err_exit 'Inf and NaN not working'
fi
unset x y n r
n=14.555
float x=$n y
y=$(printf "%a" x)
r=$y
[[ $r == $n ]] || err_exit "output of printf %a not self preserving -- expected $x, got $y"
unset x y r
x=-0
y=$(printf "%g %g %g %g %g %g\n" -0. -0 $((-0)) x $x $((x)))
r="-0 -0 -0 -0 -0 -0"
[[ $y == "$r" ]] || err_exit "-0 vs -0.0 inconsistency -- expected '$r', got '$y'"
$SHELL -c '(( x=));:' 2> /dev/null && err_exit '((x=)) should be an error'
$SHELL -c '(( x+=));:' 2> /dev/null && err_exit '((x+=)) should be an error'
$SHELL -c '(( x=+));:' 2> /dev/null && err_exit '((x=+)) should be an error'
$SHELL -c 'x=();x.arr[0]=(z=3); ((x.arr[0].z=2))' 2> /dev/null || err_exit '(((x.arr[0].z=2)) should not be an error'

float t
typeset a b r
v="-0.0 0.0 +0.0 -1.0 1.0 +1.0"
for a in $v
do	for b in $v
	do	(( r = copysign(a,b) ))
		(( t = copysign(a,b) ))
		[[ $r == $t ]] || err_exit $(printf "float t=copysign(%3.1f,%3.1f) => %3.1f -- expected %3.1f\n" a b t r)
	done
done

typeset -l y y_ascii
(( y=sin(90) )) 
y_ascii=$y 
(( y == y_ascii )) || err_exit "no match,\n\t$(printf "%a\n" y)\n!=\n\t$(printf "%a\n" y_ascii)"

( $SHELL  <<- \EOF
	p=5
	t[p]=6
	while (( t[p] != 0 )) ; do
		((
		p+=1 , 
		t[p]+=2 , 
		p+=3 , 
		t[p]+=5 , 
		p+=1 , 
		t[p]+=2 , 
		p+=1 , 
		t[p]+=1 , 
		p-=6  ,
		t[p]-=1 
		))
	:
	done
EOF) 2> /dev/null ||  err_exit 'error with comma expression'

N=(89551 89557)
i=0 j=1
[[ $(printf "%d" N[j]-N[i]) == 6 ]] || err_exit 'printf %d N[i]-N[j] failed'
[[ $((N[j]-N[i])) == 6 ]] || err_exit  '$((N[j]-N[i])) incorrect'

unset a x
x=0
((a[++x]++))
(( x==1)) || err_exit '((a[++x]++)) should only increment x once'
(( a[1]==1))  || err_exit 'a[1] not incremented'
unset a
x=0
((a[x++]++))
(( x==1)) || err_exit '((a[x++]++)) should only increment x once'
(( a[0]==1))  || err_exit 'a[0] not incremented'
unset a
x=0
((a[x+=2]+=1))
(( x==2)) || err_exit '((a[x+=2]++)) should result in x==2'
(( a[2]==1))  || err_exit 'a[0] not 1'

unset a i
typeset -a a
i=1
(( a[i]=1 ))
(( a[0] == 0 )) || err_exit 'a[0] not 0'
(( a[1] == 1 )) || err_exit 'a[1] not 1'

unset a
typeset -i a
for ((i=0;i<1000;i++))
do ((a[RANDOM%2]++))
done
(( (a[0]+a[1])==1000)) || err_exit '(a[0]+a[1])!=1000'

exit $((Errors))
