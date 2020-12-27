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

Command=${0##*/}
integer Errors=0

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

r=readonly u=Uppercase l=Lowercase i=22 i8=10 L=abc L5=def uL5=abcdef xi=20
x=export t=tagged H=hostname LZ5=026 RZ5=026 Z5=123 lR5=ABcdef R5=def n=l
for option in u l i i8 L L5 LZ5 RZ5 Z5 r x H t R5 uL5 lR5 xi n
do	typeset -$option $option
done
(r=newval) 2> /dev/null && err_exit readonly attribute fails
i=i+5
if	((i != 27))
then	err_exit integer attributes fails
fi
if	[[ $i8 != 8#12 ]]
then	err_exit integer base 8 fails
fi
if	[[ $u != UPPERCASE ]]
then	err_exit uppercase fails
fi
if	[[ $l != lowercase ]]
then	err_exit lowercase fails
fi
if	[[ $n != lowercase ]]
then	err_exit reference variables fail
fi
if	[[ t=tagged != $(typeset -t) ]]
then	err_exit tagged fails
fi
if	[[ t != $(typeset +t) ]]
then	err_exit tagged fails
fi
if	[[ $Z5 != 00123 ]]
then	err_exit zerofill fails
fi
if	[[ $RZ5 != 00026 ]]
then	err_exit right zerofill fails
fi
L=12345
if	[[ $L != 123 ]]
then	err_exit leftjust fails
fi
if	[[ $L5 != "def  " ]]
then	err_exit leftjust fails
fi
if	[[ $uL5 != ABCDE ]]
then	err_exit leftjust uppercase fails
fi
if	[[ $lR5 != bcdef ]]
then	err_exit rightjust fails
fi
if	[[ $R5 != "  def" ]]
then	err_exit rightjust fails
fi
if	[[ $($SHELL -c 'echo $x') != export ]]
then	err_exit export fails
fi
if	[[ $($SHELL -c 'xi=xi+4;echo $xi') != 24 ]]
then	err_exit export attributes fails
fi
x=$(foo=abc $SHELL <<!
	foo=bar
	$SHELL -c  'print \$foo'
!
)
if	[[ $x != bar ]]
then	err_exit 'environment variables require re-export'
fi
(typeset + ) > /dev/null 2>&1 || err_exit 'typeset + not working'
(typeset -L-5 buf="A" 2>/dev/null)
if [[ $? == 0 ]]
then	err_exit 'typeset allows negative field for left/right adjust'
fi
a=b
readonly $a=foo
if	[[ $b != foo ]]
then	err_exit 'readonly $a=b not working'
fi
if	[[ $(export | grep '^PATH=') != PATH=* ]]
then	err_exit 'export not working'
fi
picture=(
	bitmap=/fruit
	size=(typeset -E x=2.5)
)
string="$(print $picture)"
if [[ "${string}" != *'size=( typeset -E'* ]]
then	err_exit 'print of compound exponential variable not working'
fi
sz=(typeset -E y=2.2)
string="$(print $sz)"
if [[ "${sz}" == *'typeset -E -F'* ]]
then 	err_exit 'print of exponential shows both -E and -F attributes'
fi
print 'typeset -i m=48/4+1;print -- $m' > $tmp/script
chmod +x $tmp/script
typeset -Z2 m
if	[[ $($tmp/script) != 13 ]]
then	err_exit 'attributes not cleared for script execution'
fi
print 'print VAR=$VAR' > $tmp/script
typeset -L70 VAR=var
$tmp/script > $tmp/script.1
[[ $(< $tmp/script.1) == VAR= ]] || err_exit 'typeset -L should not be inherited'
typeset -Z  LAST=00
unset -f foo
function foo
{
        if [[ $1 ]]
        then    LAST=$1
        else    ((LAST++))
        fi
}
foo 1
if	(( ${#LAST} != 2 ))
then	err_exit 'LAST!=2'
fi
foo
if	(( ${#LAST} != 2 ))
then	err_exit 'LAST!=2'
fi
[[ $(set | grep LAST) == LAST=02 ]] || err_exit "LAST not correct in set list"
set -a
unset foo
foo=bar
if	[[ $(export | grep ^foo=) != 'foo=bar' ]]
then	err_exit 'all export not working'
fi
unset foo
read foo <<!
bar
!
if	[[ $(export | grep ^foo=) != 'foo=bar' ]]
then	err_exit 'all export not working with read'
fi
if	[[ $(typeset | grep PS2) == PS2 ]]
then	err_exit 'typeset without arguments outputs names without attributes'
fi
unset a z q x
w1=hello
w2=world
t1="$w1 $w2"
if	(( 'a' == 97 ))
then	b1=aGVsbG8gd29ybGQ=
	b2=aGVsbG8gd29ybGRoZWxsbyB3b3JsZA==
else	b1=iIWTk5ZAppaZk4Q=
	b2=iIWTk5ZAppaZk4SIhZOTlkCmlpmThA==
fi
z=$b1
typeset -b x=$b1
[[ $x == "$z" ]] || print -u2 'binary variable not expanding correctly'
[[  $(printf "%B" x) == $t1 ]] || err_exit 'typeset -b not working'
typeset -b -Z5 a=$b1
[[  $(printf "%B" a) == $w1 ]] || err_exit 'typeset -b -Z5 not working'
typeset -b q=$x$x
[[ $q == $b2 ]] || err_exit 'typeset -b not working with concatination'
[[  $(printf "%B" q) == $t1$t1 ]] || err_exit 'typeset -b concatination not working'
x+=$b1
[[ $x == $b2 ]] || err_exit 'typeset -b not working with append'
[[  $(printf "%B" x) == $t1$t1 ]] || err_exit 'typeset -b append not working'
typeset -b -Z20 z=$b1
(( $(printf "%B" z | wc -c) == 20 )) || err_exit 'typeset -b -Z20 not storing 20 bytes'
{
	typeset -b v1 v2
	read -N11 v1
	read -N22 v2
} << !
hello worldhello worldhello world
!
[[ $v1 == "$b1" ]] || err_exit "v1=$v1 should be $b1"
[[ $v2 == "$x" ]] || err_exit "v1=$v2 should be $x"
if	env '!=1' >/dev/null 2>&1
then	[[ $(env '!=1' $SHELL -c 'echo ok' 2>/dev/null) == ok ]] || err_exit 'malformed environment terminates shell'
fi
unset var
typeset -b var
printf '12%Z34' | read -r -N 5 var
[[ $var == MTIAMzQ= ]] || err_exit 'binary files with zeros not working'
unset var
if	command typeset -usi var=0xfffff 2> /dev/null
then	(( $var == 0xffff )) || err_exit 'unsigned short integers not working'
else	err_exit 'typeset -usi cannot be used for unsigned short'
fi
[[ $($SHELL -c 'unset foo;typeset -Z2 foo; print ${foo:-3}' 2> /dev/null) == 3 ]]  || err_exit  '${foo:-3} not 3 when typeset -Z2 field undefined'
[[ $($SHELL -c 'unset foo;typeset -Z2 foo; print ${foo:=3}' 2> /dev/null) == 03 ]]  || err_exit  '${foo:=-3} not 3 when typeset -Z2 foo undefined'
unset foo bar
unset -f fun
function fun
{
	export foo=hello
	typeset -x  bar=world
	[[ $foo == hello ]] || err_exit 'export scoping problem in function'
}
fun
[[ $(export | grep foo) == 'foo=hello' ]] || err_exit 'export not working in functions'
[[ $(export | grep bar) ]] && err_exit 'typeset -x not local'
[[ $($SHELL -c 'typeset -r IFS=;print -r $(pwd)' 2> /dev/null) == "$(pwd)" ]] || err_exit 'readonly IFS causes command substitution to fail'
fred[66]=88
[[ $(typeset -pa) == *fred* ]] || err_exit 'typeset -pa not working'
unset x y z
typeset -LZ3 x=abcd y z=00abcd
y=03
[[ $y == "3  " ]] || err_exit '-LZ3 not working for value 03'
[[ $x == "abc" ]] || err_exit '-LZ3 not working for value abcd'
[[ $x == "abc" ]] || err_exit '-LZ3 not working for value 00abcd'
unset x z
set +a
[[ $(typeset -p z) ]] && err_exit "typeset -p for z undefined failed"
unset z
x='typeset -i z=45'
eval "$x"
[[ $(typeset -p z) == "$x" ]] || err_exit "typeset -p for '$x' failed"
[[ $(typeset +p z) == "${x%=*}" ]] || err_exit "typeset +p for '$x' failed"
unset z
x='typeset -a z=(a b c)'
eval "$x"
[[ $(typeset -p z) == "$x" ]] || err_exit "typeset -p for '$x' failed"
[[ $(typeset +p z) == "${x%=*}" ]] || err_exit "typeset +p for '$x' failed"
unset z
x='typeset -C z=(
	foo=bar
	xxx=bam
)'
eval "$x"
x=${x//$'\t'}
x=${x//$'(\n'/'('}
x=${x//$'\n'/';'}
x=${x%';)'}')'
[[ $(typeset -p z) == "$x" ]] || err_exit "typeset -p for '$x' failed"
[[ $(typeset +p z) == "${x%%=*}" ]] || err_exit "typeset +p for '$x' failed"
unset z
x='typeset -A z=([bar]=bam [xyz]=bar)'
eval "$x"
[[ $(typeset -p z) == "$x" ]] || err_exit "typeset -p for '$x' failed"
[[ $(typeset +p z) == "${x%%=*}" ]] || err_exit "typeset +p for '$x' failed"
unset z
foo=abc
x='typeset -n z=foo'
eval "$x"
[[ $(typeset -p z) == "$x" ]] || err_exit "typeset -p for '$x' failed"
[[ $(typeset +p z) == "${x%%=*}" ]] || err_exit "typeset +p for '$x' failed"
typeset +n z
unset foo z
typeset -T Pt_t=(
	float x=1 y=2
)
Pt_t z
x=${z//$'\t'}
x=${x//$'(\n'/'('}
x=${x//$'\n'/';'}
x=${x%';)'}')'
[[ $(typeset -p z) == "Pt_t z=$x" ]] || err_exit "typeset -p for type failed"
[[ $(typeset +p z) == "Pt_t z" ]] || err_exit "typeset +p for type failed"
unset z
function foo
{
	typeset -p bar
}
bar=xxx
[[ $(foo) == bar=xxx ]] || err_exit 'typeset -p not working inside a function'
unset foo
typeset -L5 foo
[[ $(typeset -p foo) == 'typeset -L 5 foo' ]] || err_exit 'typeset -p not working for variables with attributes but without a value'
{ $SHELL  <<- EOF
	typeset -L3 foo=aaa
	typeset -L6 foo=bbbbbb
	[[ \$foo == bbbbbb ]]
EOF
}  || err_exit 'typeset -L should not preserve old attributes'
{ $SHELL <<- EOF
	typeset -R3 foo=aaa
	typeset -R6 foo=bbbbbb
	[[ \$foo == bbbbbb ]]
EOF
} 2> /dev/null || err_exit 'typeset -R should not preserve old attributes'

expected='YWJjZGVmZ2hpag=='
unset foo
typeset -b -Z10 foo
read foo <<< 'abcdefghijklmnop'
[[ $foo == "$expected" ]] || err_exit 'read foo, where foo is "typeset -b -Z10" not working'
unset foo
typeset -b -Z10 foo
read -N10 foo <<< 'abcdefghijklmnop'
[[ $foo == "$expected" ]] || err_exit 'read -N10 foo, where foo is "typeset -b -Z10" not working'
unset foo
typeset  -b -A foo
read -N10 foo[4] <<< 'abcdefghijklmnop'
[[ ${foo[4]} == "$expected" ]] || err_exit 'read -N10 foo, where foo is "typeset  -b -A" foo not working'
unset foo
typeset  -b -a foo
read -N10 foo[4] <<< 'abcdefghijklmnop'
[[ ${foo[4]} == "$expected" ]] || err_exit 'read -N10 foo, where foo is "typeset  -b -a" foo not working'
[[ $(printf %B foo[4]) == abcdefghij ]] || err_exit 'printf %B for binary associative array element not working'
[[ $(printf %B foo[4]) == abcdefghij ]] || err_exit 'printf %B for binary indexed array element not working'
unset foo

$SHELL 2> /dev/null -c 'export foo=(bar=3)' && err_exit 'compound variables cannot be exported'

$SHELL -c 'builtin date' >/dev/null 2>&1 &&
{

# check env var changes against a builtin that uses the env var

SEC=1234252800
ETZ=EST5EDT
EDT=03
PTZ=PST8PDT
PDT=00

CMD="date -f%H \\#$SEC"

export TZ=$ETZ

set -- \
	"$EDT $PDT $EDT"	""		"TZ=$PTZ"	"" \
	"$EDT $PDT $EDT"	""		"TZ=$PTZ"	"TZ=$ETZ" \
	"$EDT $PDT $EDT"	"TZ=$ETZ"	"TZ=$PTZ"	"TZ=$ETZ" \
	"$PDT $EDT $PDT"	"TZ=$PTZ"	""		"TZ=$PTZ" \
	"$PDT $EDT $PDT"	"TZ=$PTZ"	"TZ=$ETZ"	"TZ=$PTZ" \
	"$EDT $PDT $EDT"	"foo=bar"	"TZ=$PTZ"	"TZ=$ETZ" \

while	(( $# >= 4 ))
do	exp=$1
	got=$(print $($SHELL -c "builtin date; $2 $CMD; $3 $CMD; $4 $CMD"))
	[[ $got == $exp ]] || err_exit "[ '$2'  '$3'  '$4' ] env sequence failed -- expected '$exp', got '$got'"
	shift 4
done

}

unset v
typeset -H v=/dev/null
[[ $v == *nul* ]] || err_exit 'typeset -H for /dev/null not working'

unset x
(typeset +C x) 2> /dev/null && err_exit 'typeset +C should be an error' 
(typeset +A x) 2> /dev/null && err_exit 'typeset +A should be an error' 
(typeset +a x) 2> /dev/null && err_exit 'typeset +a should be an error' 

unset x
{
x=$($SHELL -c 'integer -s x=5;print -r -- $x')
} 2> /dev/null
[[ $x == 5 ]] || err_exit 'integer -s not working'

[[ $(typeset -l) == *namespace*.sh* ]] && err_exit 'typeset -l should not contain namespace .sh'

unset got
typeset -u got
exp=100
((got=$exp))
[[ $got == $exp ]] || err_exit "typeset -l fails on numeric value -- expected '$exp', got '$got'"

unset s
typeset -a -u s=( hello world chicken )
[[ ${s[2]} == CHICKEN ]] || err_exit 'typeset -u not working with indexed arrays'
unset s
typeset -A -u s=( [1]=hello [0]=world [2]=chicken )
[[ ${s[2]} == CHICKEN ]] || err_exit 'typeset -u not working with associative arrays'
expected=$'(\n\t[0]=WORLD\n\t[1]=HELLO\n\t[2]=CHICKEN\n)'
[[ $(print -v s) == "$expected" ]] || err_exit 'typeset -u for associative array does not display correctly'

unset s
if	command typeset -M totitle s 2> /dev/null
then	[[ $(typeset +p s) == 'typeset -M totitle s' ]] || err_exit 'typeset -M totitle does not display correctly with typeset -p'
fi

{ $SHELL  <<-  \EOF
	compound -a a1
	for ((i=1 ; i < 100 ; i++ ))
        do	[[ "$( typeset + a1[$i] )" == '' ]] && a1[$i].text='hello'
	done
	[[ ${a1[70].text} == hello ]]
EOF
} 2> /dev/null
(( $? )) && err_exit  'typeset + a[i] not working'

typeset groupDB="" userDB=""
typeset -l -L1 DBPick=""
[[ -n "$groupDB" ]]  && err_exit 'typeset -l -L1 causes unwanted side effect'

HISTFILE=foo
typeset -u PS1='hello --- '
HISTFILE=foo
[[ $HISTFILE == foo ]] || err_exit  'typeset -u PS1 affects HISTFILE'

typeset -a a=( aA= ZQ= bA= bA= bw= Cg= )
typeset -b x
for 	(( i=0 ; i < ${#a[@]} ; i++ ))
do 	x+="${a[i]}"
done
[[ $(printf "%B" x) == hello ]] || err_exit "append for typeset -b not working: got '$(printf "%B" x)' should get hello"

(
	trap 'exit $?' EXIT
	$SHELL -c 'typeset v=foo; [[ $(typeset -p v[0]) == v=foo ]]'
) 2> /dev/null || err_exit 'typeset -p v[0] not working for simple variable v'

unset x
expected='typeset -a x=(a\=3 b\=4)'
typeset -a x=( a=3 b=4)
[[ $(typeset -p x) == "$expected" ]] || err_exit 'assignment elements in typeset -a assignment not working'

unset z
z='typeset -a q=(a b c)'
$SHELL -c "$z; [[ \$(typeset -pa) == '$z' ]]" || err_exit 'typeset -pa does not list only index arrays'
z='typeset -C z=(foo=bar)'
$SHELL -c "$z; [[ \$(typeset -pC) == '$z' ]]" || err_exit 'typeset -pC does not list only compound variables'
unset y
z='typeset -A y=([a]=foo)'
$SHELL -c "$z; [[ \$(typeset -pA) == '$z' ]]" || err_exit 'typeset -pA does not list only associative arrays'

$SHELL 2> /dev/null -c 'typeset -C arr=( aa bb cc dd )' && err_exit 'invalid compound variable assignment not reported'

unset x
typeset -l x=
[[ ${x:=foo} == foo ]] || err_exit '${x:=foo} with x unset, not foo when x is a lowercase variable'

unset x
typeset -L4 x=$'\001abcdef'
[[ ${#x} == 5 ]] || err_exit "width of character '\01' is not zero" 

unset x
typeset -L x=-1
command typeset -F x=0-1 2> /dev/null || err_exit 'typeset -F after typeset -L fails'

unset val
typeset -i val=10#0-3
typeset -Z val=0-1
[[ $val == 0-1 ]] || err_exit 'integer attribute not cleared for subsequent typeset'

unset x
typeset -L -Z x=foo
[[ $(typeset -p x) == 'typeset -Z 3 -L 3 x=foo' ]] || err_exit '-LRZ without [n] not defaulting to width of variable'

unset foo
typeset -Z2 foo=3
[[ $(typeset -p foo) == 'typeset -Z 2 -R 2 foo=03' ]] || err_exit '-Z2  not working'
export foo
[[ $(typeset -p foo) == 'typeset -x -Z 2 -R 2 foo=03' ]] || err_exit '-Z2  not working after export'

exit $((Errors<125?Errors:125))
