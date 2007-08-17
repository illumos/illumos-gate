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
function checkref
{
	nameref foo=$1 bar=$2
	if	[[ $foo !=  $bar ]]
	then	err_exit "foo=$foo != bar=$bar"
	fi
	foo=hello
	if	[[ $foo !=  $bar ]]
	then	err_exit "foo=$foo != bar=$bar"
	fi
	foo.child=child
	if	[[ ${foo.child} !=  ${bar.child} ]]
	then	err_exit "foo.child=${foo.child} != bar=${bar.child}"
	fi
}

name=first
checkref name name
name.child=second
checkref name name
.foo=top
.foo.bar=next
checkref .foo.bar .foo.bar
if	[[ ${.foo.bar} !=  hello ]]
then	err_exit ".foo.bar=${.foo.bar} != hello"
fi
if	[[ ${.foo.bar.child} !=  child ]]
then	err_exit ".foo.bar.child=${.foo.bar.child} != child"
fi
function func1
{
        nameref color=$1
        func2 color
}

function func2
{
        nameref color=$1
        set -s -- ${!color[@]}
	print -r -- "$@"
}

typeset -A color
color[apple]=red
color[grape]=purple
color[banana]=yellow
if	[[ $(func1 color) != 'apple banana grape' ]]
then	err_exit "nameref or nameref not working"
fi
nameref x=.foo.bar
if	[[ ${!x} != .foo.bar ]]
then	err_exit "${!x} not working"
fi
typeset +n x $(typeset +n) 
unset x
nameref x=.foo.bar
function x.set
{
	[[ ${.sh.value} ]] && print hello
}
if	[[ $(.foo.bar.set) != $(x.set) ]]
then	err_exit "function references  not working"
fi
if	[[ $(typeset +n) != x ]]
then	err_exit "typeset +n doesn't list names of reference variables"
fi
if	[[ $(typeset -n) != x=.foo.bar ]]
then	err_exit "typeset +n doesn't list values of reference variables"
fi
file=/tmp/shtest$$
typeset +n foo bar 2> /dev/null
unset foo bar
export bar=foo
nameref foo=bar
if	[[ $foo != foo ]]
then	err_exit "value of nameref foo !=  $foo"
fi
trap "rm -f $file" EXIT INT
cat > $file <<\!
print -r -- $foo
!
chmod +x "$file"
y=$( $file)
if	[[ $y != '' ]]
then	err_exit "reference variable not cleared"
fi
{ 
	command nameref xx=yy
	command nameref yy=xx
} 2> /dev/null && err_exit "self reference not detected"
typeset +n foo bar
unset foo bar
set foo
nameref bar=$1
foo=hello
if	[[ $bar !=  hello ]]
then	err_exit 'nameref of positional paramters outside of function not working'
fi
unset foo bar
bar=123
function foobar 
{
	typeset -n foo=bar
	typeset -n foo=bar
}
foobar 2> /dev/null || err_exit 'nameref not unsetting previous reference'
(
	nameref short=verylong
	short=( A=a B=b )
	if	[[ ${verylong.A} != a ]]
	then	err_exit 'nameref short to longname compound assignment error'
	fi
) 2> /dev/null|| err_exit 'nameref short to longname compound assignment error'
unset x
if	[[	$(var1=1 var2=2
		for i in var1 var2
		do	nameref x=$i
			print $x
		done) != $'1\n2' ]]
then	err_exit 'for loop nameref optimization error'
fi
if	[[	$(typeset -A var1 var2
		var1[sub1]=1 var2[sub2]=1
		for i in var1 var2
		do
		        typeset -n array=$i
		        print ${!array[*]}
		done) != $'sub1\nsub2' ]]
then 	err_exit 'for loop nameref optimization test2 error'
fi

unset -n x foo bar
if	[[ $(nameref x=foo;for x in foo bar;do print ${!x};done) != $'foo\nbar' ]]
then	err_exit 'for loop optimization with namerefs not working'
fi
if	[[ $(
	p=(x=(r=3) y=(r=4))
	for i in x y
	do	nameref x=p.$i
		print ${x.r}
	done
) != $'3\n4' ]]
then	err_exit 'nameref optimization error'
fi
[[ $(
unset x y var
var=(foo=bar)
for i in y var
do	typeset -n x=$i
	if	[[ ${!x.@} ]]
	then	print ok
	fi
	typeset +n x
done) != ok ]] && err_exit 'invalid for loop optimization of name references'
function setval # name value
{
        nameref arg=$1
	nameref var=arg.bar
	var=$2
}
foo=( integer bar=0)
setval foo 5
(( foo.bar == 5)) || err_exit 'nested nameref not working'
function selfref
{
        typeset -n ps=$1
        print -r -- "${ps}"
}
ps=(a=1 b=2)
[[ $(selfref ps) == *a=1* ]] ||  err_exit 'local nameref cannot reference global variable of the same name'
function subref
{
	typeset -n foo=$1
	print -r -- ${foo.a}
}
[[ $(subref ps) == 1 ]] ||  err_exit 'local nameref cannot reference global variable child'

function local
{
	typeset ps=(typeset -i a=3 b=4)
	[[ $(subref ps) == 3 ]] ||  err_exit 'local nameref cannot reference caller compound variable'
}
local
unset -f local
function local
{
	qs=(integer  a=3; integer b=4)
}
local 2> /dev/null || err_exit 'function local has non-zero exit status'
[[ ${qs.a} == 3 ]] || err_exit 'function cannot set compound global variable' 
unset fun i
foo=(x=hi)
function fun
{
        nameref i=$1
        print -r -- "${i.x}"
}
i=foo
[[ $(fun $i) == hi ]] || err_exit 'nameref for compound variable with in function name of caller fails'
exit $((Errors))
