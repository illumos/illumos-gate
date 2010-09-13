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
file=$tmp/test
typeset +n foo bar 2> /dev/null
unset foo bar
export bar=foo
nameref foo=bar
if	[[ $foo != foo ]]
then	err_exit "value of nameref foo !=  $foo"
fi
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
unset -n foo bar
typeset -A foo
foo[x.y]=(x=3 y=4)
nameref bar=foo[x.y]
[[ ${bar.x} == 3 ]] || err_exit 'nameref to subscript containing . fails'
[[ ${!bar} == 'foo[x.y]' ]] || err_exit '${!var} not correct for nameref to an array instance'
typeset +n bar
nameref bar=foo
[[ ${!bar} == foo ]] || err_exit '${!var} not correct for nameref to array variable'
$SHELL -c 'function bar { nameref x=foo[++];};typeset -A foo;bar' 2> /dev/null ||err_exit 'nameref of associative array tries to evaluate subscript'
i=$($SHELL -c 'nameref foo=bar; bar[2]=(x=3 y=4); nameref x=foo[2].y;print -r -- $x' 2> /dev/null)
[[ $i == 4 ]] || err_exit 'creating reference from subscripted variable whose name is a reference failed'
[[ $($SHELL 2> /dev/null <<- '+++EOF'
	function bar
	{
	 	nameref x=$1
	 	print -r -- "$x"
	}
	function foo
	{
	 	typeset var=( foo=hello)
	 	bar var
	}
	foo
+++EOF
) ==  *foo=hello* ]] || err_exit 'unable to display compound variable from name reference of local variable'
#set -x
for c in '=' '[' ']' '\' "'" '"' '<' '=' '('
do	[[ $($SHELL 2> /dev/null <<- ++EOF++
	x;i=\\$c;typeset -A a; a[\$i]=foo;typeset -n x=a[\$i]; print "\$x"
	++EOF++
) != foo ]] && err_exit 'nameref x=[$c] '"not working for c=$c"
done
unset -n foo x
unset foo x
typeset -A foo
nameref x=foo[xyz]
foo[xyz]=ok
[[ $x == ok ]] || err_exit 'nameref to unset subscript not working'
function function2
{
	nameref v=$1
	v.x=19 v.y=20
}
function function1
{
	typeset compound_var=()
	function2 compound_var
	printf "x=%d, y=%d\n" compound_var.x compound_var.y
}
x="$(function1)"
[[ "$x" != 'x=19, y=20' ]] && err_exit "expected 'x=19, y=20', got '${x}'"
typeset +n bar
unset foo bar
[[ $(function a
{
	for i in  foo bar
	do	typeset -n v=$i
		print $v
	done | cat
}
foo=1 bar=2;a) == $'1\n2' ]] 2> /dev/null || err_exit 'nameref in pipeline broken'
function a
{
	typeset -n v=vars.data._1
	print "${v.a} ${v.b}"
}
vars=(data=())
vars.data._1.a=a.1
vars.data._1.b=b.1
[[ $(a) == 'a.1 b.1' ]] || err_exit 'nameref choosing wrong scope -- '
typeset +n bam zip foo
unset bam zip foo
typeset -A foo
foo[2]=bar
typeset -n bam=foo[2]
typeset -n zip=bam
[[ $zip == bar ]] || err_exit 'nameref to another nameref to array element fails'
[[ -R zip ]] || err_exit '[[ -R zip ]] should detect that zip is a reference'
[[ -R bam ]] || err_exit '[[ -R bam ]] should detect that bam is a reference'
[[ -R zip ]] || err_exit '[[ -v zip ]] should detect that zip is set'
[[ -v bam ]] || err_exit '[[ -v bam ]] should detect that bam is set'
[[ -R 123 ]] && err_exit '[[ -R 123 ]] should detect that 123 is not a reference'
[[ -v 123 ]] && err_exit '[[ -v 123 ]] should detect that 123 is not set'

unset ref x
typeset -n ref
x=3
function foobar
{
	typeset xxx=3
	ref=xxx
	return 0
}
foobar 2> /dev/null && err_exit 'invalid reference should cause foobar to fail'
[[ -v ref ]] && err_exit '$ref should be unset'
ref=x
[[ $ref == 3 ]] || err_exit "\$ref is $ref, it should be 3"
function foobar
{
        typeset fvar=()
        typeset -n ref=fvar.foo
        ref=ok
        print -r $ref
}
[[ $(foobar) ==  ok ]] 2> /dev/null  || err_exit 'nameref in function not creating variable in proper scope'
function foobar
{
        nameref doc=docs
        nameref bar=doc.num
	[[ $bar == 2 ]] || err_exit 'nameref scoping error'
}

docs=(num=2)
foobar

typeset +n x y
unset x y
typeset -A x
x[a]=(b=c)  
typeset -n y=x[a]
[[ ${!y.@} == 'x[a].b' ]] || err_exit 'reference to array element not expanded with ${!y.@}'

typeset +n v
v=()
k=a.b.c/d
command typeset -n n=v.${k//['./']/_} 2> /dev/null || err_exit 'patterns with quotes not handled correctly with name reference assignment'

typeset _n sp
nameref sp=addrsp
sp[14]=( size=1 )
[[ -v sp[19] ]]  && err_exit '[[ -v sp[19] ]] where sp is a nameref should not be set'

exit $((Errors))
