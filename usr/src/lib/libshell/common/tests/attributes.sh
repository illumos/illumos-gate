########################################################################
#                                                                      #
#               This software is part of the ast package               #
#           Copyright (c) 1982-2007 AT&T Knowledge Ventures            #
#                      and is licensed under the                       #
#                  Common Public License, Version 1.0                  #
#                      by AT&T Knowledge Ventures                      #
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
print 'typeset -i m=48/4+1;print -- $m' > /tmp/ksh$$
chmod +x /tmp/ksh$$
typeset -Z2 m
if	[[ $(/tmp/ksh$$) != 13 ]]
then	err_exit 'attributes not cleared for script execution'
fi
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
rm -rf /tmp/ksh$$
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
[[ $(env '!=1' $SHELL -c 'echo ok' 2>/dev/null) == ok ]] || err_exit 'malformed environment terminates shell'
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
exit	$((Errors))
