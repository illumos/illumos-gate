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

function fun
{
	integer i
	unset xxx
	for i in 0 1
	do	xxx[$i]=$i
	done
}

set -A x zero one two three four 'five six'
if	[[ $x != zero ]]
then	err_exit '$x is not element 0'
fi
if	[[ ${x[0]} != zero ]]
then	err_exit '${x[0] is not element 0'
fi
if	(( ${#x[0]} != 4 ))
then	err_exit "length of ${x[0]} is not 4"
fi
if	(( ${#x[@]} != 6  ))
then	err_exit 'number of elements of x is not 6'
fi
if	[[ ${x[2]} != two  ]]
then	err_exit ' element two is not 2'
fi
if	[[ ${x[@]:2:1} != two  ]]
then	err_exit ' ${x[@]:2:1} is not two'
fi
set -A y -- ${x[*]}
if	[[ $y != zero ]]
then	err_exit '$x is not element 0'
fi
if	[[ ${y[0]} != zero ]]
then	err_exit '${y[0] is not element 0'
fi
if	(( ${#y[@]} != 7  ))
then	err_exit 'number of elements of y is not 7'
fi
if	[[ ${y[2]} != two  ]]
then	err_exit ' element two is not 2'
fi
set +A y nine ten
if	[[ ${y[2]} != two  ]]
then	err_exit ' element two is not 2'
fi
if	[[ ${y[0]} != nine ]]
then	err_exit '${y[0] is not nine'
fi
unset y[4]
if	(( ${#y[@]} != 6  ))
then	err_exit 'number of elements of y is not 6'
fi
if	(( ${#y[4]} != 0  ))
then	err_exit 'string length of unset element is not 0'
fi
unset foo
if	(( ${#foo[@]} != 0  ))
then	err_exit 'number of elements of unset variable foo is not 0'
fi
foo=''
if	(( ${#foo[0]} != 0  ))
then	err_exit 'string length of null element is not 0'
fi
if	(( ${#foo[@]} != 1  ))
then	err_exit 'number of elements of null variable foo is not 1'
fi
unset foo
foo[0]=foo
foo[3]=bar
unset foo[0]
unset foo[3]
if	(( ${#foo[@]} != 0  ))
then	err_exit 'number of elements of left in variable foo is not 0'
fi
unset foo
foo[3]=bar
foo[0]=foo
unset foo[3]
unset foo[0]
if	(( ${#foo[@]} != 0  ))
then	err_exit 'number of elements of left in variable foo again is not 0'
fi
fun
if	(( ${#xxx[@]} != 2  ))
then	err_exit 'number of elements of left in variable xxx is not 2'
fi
fun
if	(( ${#xxx[@]} != 2  ))
then	err_exit 'number of elements of left in variable xxx again is not 2'
fi
set -A foo -- "${x[@]}"
if	(( ${#foo[@]} != 6  ))
then	err_exit 'number of elements of foo is not 6'
fi
if	(( ${#PWD[@]} != 1  ))
then	err_exit 'number of elements of PWD is not 1'
fi
unset x
x[2]=foo x[4]=bar
if	(( ${#x[@]} != 2  ))
then	err_exit 'number of elements of x is not 2'
fi
s[1]=1 c[1]=foo
if	[[ ${c[s[1]]} != foo ]]
then	err_exit 'c[1]=foo s[1]=1; ${c[s[1]]} != foo'
fi
unset s
typeset -Ai s
y=* z=[
s[$y]=1
s[$z]=2
if	(( ${#s[@]} != 2  ))
then	err_exit 'number of elements of  is not 2'
fi
(( s[$z] = s[$z] + ${s[$y]} ))
if	[[ ${s[$z]} != 3  ]]
then	err_exit '[[ ${s[$z]} != 3  ]]'
fi
if	(( s[$z] != 3 ))
then	err_exit '(( s[$z] != 3 ))'
fi
(( s[$y] = s[$y] + ${s[$z]} ))
if	[[ ${s[$y]} != 4  ]]
then	err_exit '[[ ${s[$y]} != 4  ]]'
fi
if	(( s[$y] != 4 ))
then	err_exit '(( s[$y] != 4 ))'
fi
set -A y 2 4 6
typeset -i y
z=${y[@]}
typeset -R12 y
typeset -i y
if      [[ ${y[@]} != "$z" ]]
then    err_exit 'error in array conversion from int to R12'
fi
if      (( ${#y[@]} != 3  ))
then    err_exit 'error in count of array conversion from int to R12'
fi
unset abcdefg
:  ${abcdefg[1]}
set | grep '^abcdefg$' >/dev/null && err_exit 'empty array variable in set list'
unset x y
x=1
typeset -i y[$x]=4
if	[[ ${y[1]} != 4 ]]
then    err_exit 'arithmetic expressions in typeset not working'
fi
unset foo
typeset foo=bar
typeset -A foo
if	[[ ${foo[0]} != bar ]]
then	err_exit 'initial value not preserved when typecast to associative'
fi
unset foo
foo=(one two)
typeset -A foo
foo[two]=3
if	[[ ${#foo[*]} != 3 ]]
then	err_exit 'conversion of indexed to associative array failed'
fi
set a b c d e f g h i j k l m
if	[[ ${#} != 13 ]]
then	err_exit '${#} not 13'
fi
unset xxx
xxx=foo
if	[[ ${!xxx[@]} != 0 ]]
then	err_exit '${!xxx[@]} for scalar not 0'
fi
if	[[ ${11} != k ]]
then	err_exit '${11} not working'
fi
if	[[ ${@:4:1} != d ]]
then	err_exit '${@:4:1} not working'
fi
foovar1=abc
foovar2=def
if	[[ ${!foovar@} != +(foovar[[:alnum:]]?([ ])) ]]
then	err_exit '${!foovar@} does not expand correctly'
fi
if	[[ ${!foovar1} != foovar1 ]]
then	err_exit '${!foovar1} != foovar1'
fi
unset xxx
: ${xxx[3]}
if	[[ ${!xxx[@]} ]]
then	err_exit '${!xxx[@]} should be null'
fi
integer i=0
{
	set -x
	xxx[++i]=1
	set +x
} 2> /dev/null
if	(( i != 1))
then	err_exit 'execution trace side effects with array subscripts'
fi
unset list
: $(set -A list foo bar)
if	(( ${#list[@]} != 0))
then	err_exit '$(set -A list ...) leaves side effects'
fi
unset list
list= (foo bar bam)
( set -A list one two three four)
if	[[ ${list[1]} != bar ]]
then	err_exit 'array not restored after subshell'
fi
XPATH=/bin:/usr/bin:/usr/ucb:/usr/local/bin:.:/sbin:/usr/sbin
xpath=( $( IFS=: ; echo $XPATH ) )
if	[[ $(print -r  "${xpath[@]##*/}") != 'bin bin ucb bin . sbin sbin' ]]
then	err_exit '${xpath[@]##*/} not applied to each element'
fi
foo=( zero one '' three four '' six)
integer n=-1
if	[[ ${foo[@]:n} != six ]]
then	err_exit 'array offset of -1 not working'
fi
if	[[ ${foo[@]: -3:1} != four ]]
then	err_exit 'array offset of -3:1 not working'
fi
$SHELL -c 'x=(if then else fi)' 2> /dev/null  || err_exit 'reserved words in x=() assignment not working'
unset foo
foo=one
foo=( $foo two)
if	[[ ${#foo[@]} != 2 ]]
then	err_exit 'array getting unset before right hand side evaluation'
fi
foo=(143 3643 38732)
export foo
typeset -i foo
if	[[ $($SHELL -c 'print $foo') != 143 ]]
then	err_exit 'exporting indexed array not exporting 0-th element'
fi
( $SHELL   -c '
	unset foo
	typeset -A foo=([0]=143 [1]=3643 [2]=38732)
	export foo
	typeset -i foo
	[[ $($SHELL -c "print $foo") == 143 ]]'
) 2> /dev/null ||
		err_exit 'exporting associative array not exporting 0-th element'
unset foo
typeset -A foo
foo[$((10))]=ok 2> /dev/null || err_exit 'arithmetic expression as subscript not working'
unset foo
typeset -A foo
integer foo=0
[[ $foo == 0 ]] || err_exit 'zero element of associative array not being set'
unset foo
typeset -A foo=( [two]=1)
for i in one three four five
do	: ${foo[$i]}
done
if	[[ ${!foo[@]} != two ]]
then	err_exit 'error in subscript names'
fi
unset x
x=( 1 2 3)
(x[1]=8)
[[ ${x[1]} == 2 ]] || err_exit 'index array produce side effects in subshells'
x=( 1 2 3)
(
	x+=(8)
	[[ ${#x[@]} == 4 ]] || err_exit 'index array append in subshell error'
)
[[ ${#x[@]} == 3 ]] || err_exit 'index array append in subshell effects parent'
x=( [one]=1 [two]=2 [three]=3)
(x[two]=8)
[[ ${x[two]} == 2 ]] || err_exit 'associative array produce side effects in subshells'
unset x
x=( [one]=1 [two]=2 [three]=3)
(
	x+=( [four]=4 )
	[[ ${#x[@]} == 4 ]] || err_exit 'associative array append in subshell error'
)
[[ ${#x[@]} == 3 ]] || err_exit 'associative array append in subshell effects parent'
unset x
integer i
for ((i=0; i < 40; i++))
do	x[i]=$i
done
[[  ${#x[@]} == 40 ]] || err_exit 'index arrays loosing values'
[[ $( ($SHELL -c 'typeset -A var; (IFS=: ; set -A var a:b:c ;print ${var[@]});:' )2>/dev/null) == 'a b c' ]] || err_exit 'change associative to index failed'
unset foo
[[ $(foo=good
for ((i=0; i < 2; i++))
do	[[ ${foo[i]} ]] && print ok
done) == ok ]] || err_exit 'invalid optimization for subscripted variables'
(
x=([foo]=bar)
set +A x bam
) 2> /dev/null && err_exit 'set +A with associative array should be an error'
unset bam foo
foo=0
typeset -A bam
unset bam[foo]
bam[foo]=value
[[ $bam == value ]] && err_exit 'unset associative array element error'
: only first element of an array can be exported
unset bam
print 'print ${var[0]} ${var[1]}' > $tmp/script
chmod +x $tmp/script
[[ $($SHELL -c "var=(foo bar);export var;$tmp/script") == foo ]] || err_exit 'export array not exporting just first element'

unset foo
set --allexport
foo=one
foo[1]=two
foo[0]=three
[[ $foo == three ]] || err_exit '--allexport not working with arrays'
set --noallexport
unset foo

cat > $tmp/script <<- \!
	typeset -A foo
	print foo${foo[abc]}
!
[[ $($SHELL -c "typeset -A foo;$tmp/script")  == foo ]] 2> /dev/null || err_exit 'empty associative arrays not being cleared correctly before scripts'
[[ $($SHELL -c "typeset -A foo;foo[abc]=abc;$tmp/script") == foo ]] 2> /dev/null || err_exit 'associative arrays not being cleared correctly before scripts'
unset foo
foo=(one two)
[[ ${foo[@]:1} == two ]] || err_exit '${foo[@]:1} == two'
[[ ! ${foo[@]:2} ]] || err_exit '${foo[@]:2} not null'
unset foo
foo=one
[[ ! ${foo[@]:1} ]] || err_exit '${foo[@]:1} not null'
function EMPTY
{
        typeset i
        typeset -n ARRAY=$1
        for i in ${!ARRAY[@]}
        do      unset ARRAY[$i]
        done
}
unset foo
typeset -A foo
foo[bar]=bam
foo[x]=y
EMPTY foo
[[ $(typeset | grep foo$) == *associative* ]] || err_exit 'array lost associative attribute'
[[ ! ${foo[@]}  ]] || err_exit 'array not empty'
[[ ! ${!foo[@]}  ]] || err_exit 'array names not empty'
unset foo
foo=bar
set -- "${foo[@]:1}"
(( $# == 0 )) || err_exit '${foo[@]:1} should not have any values'
unset bar
exp=4
: ${_foo[bar=4]}
(( bar == 4 )) || err_exit "subscript of unset variable not evaluated -- expected '4', got '$got'"
unset bar
: ${_foo[bar=$exp]}
(( bar == $exp )) || err_exit "subscript of unset variable not evaluated -- expected '$exp', got '$got'"
unset foo bar
foo[5]=4
bar[4]=3
bar[0]=foo
foo[0]=bam
foo[4]=5
[[ ${!foo[2+2]} == 'foo[4]' ]] || err_exit '${!var[sub]} should be var[sub]'
[[ ${bar[${foo[5]}]} == 3 ]] || err_exit  'array subscript cannot be an array instance'
[[ $bar[4] == 3 ]] || err_exit '$bar[x] != ${bar[x]} inside [[ ]]'
(( $bar[4] == 3  )) || err_exit '$bar[x] != ${bar[x]} inside (( ))'
[[ $bar[$foo[5]] == 3 ]]  || err_exit '$bar[foo[x]] != ${bar[foo[x]]} inside [[ ]]'
(( $bar[$foo[5]] == 3  )) || err_exit '$bar[foo[x]] != ${bar[foo[x]]} inside (( ))'
x=$bar[4]
[[ $x == 4 ]] && err_exit '$bar[4] should not be an array in an assignment'
x=${bar[$foo[5]]}
(( $x == 3 )) || err_exit '${bar[$foo[sub]]} not working'
[[ $($SHELL  <<- \++EOF+++
	typeset -i test_variable=0
	typeset -A test_array
	test_array[1]=100
	read test_array[2] <<-!
	2
	!
	read test_array[3] <<-!
	3
	!
	test_array[3]=4
	print "val=${test_array[3]}"
++EOF+++
) == val=4 ]] 2> /dev/null || err_exit 'after reading array[j] and assign array[j] fails'
[[ $($SHELL <<- \+++EOF+++
	pastebin=( typeset -a form)
	pastebin.form+=( name="name"   data="clueless" )
	print -r -- ${pastebin.form[0].name}
+++EOF+++
) == name ]] 2> /dev/null ||  err_exit 'indexed array in compound variable not working'
unset foo bar
: ${foo[bar=2]}
[[ $bar == 2 ]] || err_exit 'subscript not evaluated for unset variable'
unset foo bar
bar=1
typeset -a foo=([1]=ok [2]=no)
[[ $foo[bar] == ok ]] || err_exit 'typeset -a not working for simple assignment'
unset foo
typeset -a foo=([1]=(x=ok) [2]=(x=no))
[[ $(typeset | grep 'foo$') == *index* ]] || err_exit 'typeset -a not creating an indexed array'
foo+=([5]=good)
[[ $(typeset | grep 'foo$') == *index* ]] || err_exit 'append to indexed array not preserving array type'
unset foo
typeset -A foo=([1]=ok [2]=no)
[[ $foo[bar] == ok ]] && err_exit 'typeset -A not working for simple assignment'
unset foo
typeset -A foo=([1]=(x=ok) [2]=(x=no))
[[ ${foo[bar].x} == ok ]] && err_exit 'typeset -A not working for compound assignment'
[[ $($SHELL -c 'typeset -a foo;typeset | grep "foo$"'  2> /dev/null) == *index* ]] || err_exit 'typeset fails for indexed array with no elements'
xxxxx=(one)
[[ $(typeset | grep xxxxx$) == *'indexed array'* ]] || err_exit 'array of one element not an indexed array'
unset foo
foo[1]=(x=3 y=4)
{ [[ ${!foo[1].*} == 'foo[1].x foo[1].y' ]] ;} 2> /dev/null || err_exit '${!foo[sub].*} not expanding correctly'
unset x
x=( typeset -a foo=( [0]="a" [1]="b" [2]="c" ))
[[  ${@x.foo} == 'typeset -a'* ]] || err_exit 'x.foo is not an indexed array'
x=( typeset -A foo=( [0]="a" [1]="b" [2]="c" ))
[[  ${@x.foo} == 'typeset -A'* ]] || err_exit 'x.foo is not an associative array'
$SHELL -c $'x=(foo\n\tbar\nbam\n)' 2> /dev/null || err_exit 'compound array assignment with new-lines not working'
$SHELL -c $'x=(foo\n\tbar:\nbam\n)' 2> /dev/null || err_exit 'compound array assignment with labels not working'
$SHELL -c $'x=(foo\n\tdone\nbam\n)' 2> /dev/null || err_exit 'compound array assignment with reserved words not working'
[[ $($SHELL -c 'typeset -A A; print $(( A[foo].bar ))' 2> /dev/null) == 0 ]] || err_exit 'unset variable not evaluating to 0'
unset a
typeset -A a
a[a].z=1
a[z].z=2
unset a[a]
[[ ${!a[@]} == z ]] || err_exit '"unset a[a]" unsets entire array'
unset a
a=([x]=1 [y]=2 [z]=(foo=3 bar=4))
eval "b=$(printf "%B\n" a)"
eval "c=$(printf "%#B\n" a)"
[[ ${a[*]} == "${b[*]}" ]] || err_exit 'printf %B not preserving values for arrays'
[[ ${a[*]} == "${c[*]}" ]] || err_exit 'printf %#B not preserving values for arrays'
unset a
a=(zero one two three four)
a[6]=six
[[ ${a[-1]} == six ]] || err_exit 'a[-1] should be six'
[[ ${a[-3]} == four ]] || err_exit 'a[-3] should be four'
[[ ${a[-3..-1]} == 'four six' ]] || err_exit "a[-3,-1] should be 'four six'"

FILTER=(typeset scope)
FILTER[0].scope=include
FILTER[1].scope=exclude
[[ ${#FILTER[@]} == 2 ]] ||  err_exit "FILTER array should have two elements not ${#FILTER[@]}"

unset x
function x.get
{
	print sub=${.sh.subscript}
}
x[2]=
z=$(: ${x[1]} )
[[ $z == sub=1 ]] || err_exit 'get function not invoked for index array'

unset x
typeset -A x
function x.get
{
	print sub=${.sh.subscript}
}
x[2]=
z=$(: ${x[1]} )
[[ $z == sub=1 ]] || err_exit 'get function not invoked for associative array'

unset y
i=1
a=(11 22)
typeset -m y=a[i]
[[ $y == 22 ]] || err_exit 'typeset -m for index array not working'
[[ ${a[i]} || ${a[0]} != 11 ]] && err_exit 'typeset -m for index array not deleting element'

unset y
a=([0]=11 [1]=22)
typeset -m y=a[$i]
[[ $y == 22 ]] || err_exit 'typeset -m for associative array not working'
[[ ${a[$i]} || ${a[0]} != 11 ]] && err_exit 'typeset -m for associative array not deleting element'
unset x a j

typeset -a a=( [0]="aa" [1]="bb" [2]="cc" )
typeset -m 'j=a[0]'
typeset -m 'a[0]=a[1]'
typeset -m 'a[1]=j'
[[ ${a[@]} == 'bb aa cc' ]] || err_exit 'moving index array elements not working'
unset a j

typeset -A a=( [0]="aa" [1]="bb" [2]="cc" )
typeset -m 'j=a[0]'
typeset -m 'a[0]=a[1]'
typeset -m 'a[1]=j'
[[ ${a[@]} == 'bb aa cc' ]] || err_exit 'moving associative array elements not working'
unset a j

z=(a b c)
unset x
typeset -m x[1]=z
[[ ${x[1][@]} == 'a b c' ]] || err_exit 'moving indexed array to index array element not working'

unset x z
z=([0]=a [1]=b [2]=c)
typeset -m x[1]=z
[[ ${x[1][@]} == 'a b c' ]] || err_exit 'moving associative array to index array element not working'

{
typeset -a arr=(
	float
)
} 2> /dev/null
[[ ${arr[0]} == float ]] || err_exit 'typeset -a should not expand alias for float'
unset arr

{
typeset -r -a arr=(
	float
)
} 2> /dev/null
[[ ${arr[0]} == float ]] || err_exit 'typeset -r -a should not expand alias for float'
{
typeset -a arr2=(
	typeset +r
)
} 2> /dev/null
[[ ${arr2[0]} == typeset ]] || err_exit 'typeset -a should not process declarations'
unset arr2

$SHELL 2> /dev/null -c $'typeset -a arr=(\nfor)' || err_exit 'typeset -a should allow reserved words as first argument'

$SHELL 2> /dev/null -c $'typeset -r -a arr=(\nfor)' || err_exit 'typeset -r -a should allow reserved words as first argument'

typeset arr2[6]
[[ ${#arr2[@]} == 0 ]] || err_exit 'declartion "typeset array[6]" should not show any elements'

arr2[1]=def
[[ ${arr2[1]} == def ]] || err_exit 'declaration "typeset array[6]" causes arrays causes wrong side effects'

unset foo
typeset foo[7]
[[ ${#foo[@]} == 0 ]] || err_exit 'typeset foo[7] should not have one element' 

a=123 $SHELL  2> /dev/null -c 'integer a[5]=3 a[2]=4; unset a;x=0; ((a[++x]++));:' || err_exit 'unsetting array variable leaves side effect'

unset foo
foo=(aa bb cc)
foo=( ${foo[@]:1} )
[[ ${foo[@]} == 'bb cc' ]] || err_exit "indexed array assignment using parts of array for values gives wrong result of ${foo[@]}"

unset foo
foo=([xx]=aa [yy]=bb [zz]=cc)
foo=( ${foo[yy]} ${foo[zz]} )
[[ ${foo[@]} == 'bb cc' ]] || err_exit "associative array assignment using parts of array for values gives wrong result of ${foo[@]}"

unset foo
typeset -a foo=(abc=1 def=2)
[[ ${foo[1]} == def=2 ]] || err_exit "index array with elements containing = not working"

unset foo
typeset -a foo=( a b )
typeset -p foo[10]
[[ ${!foo[@]} == '0 1' ]] || err_exit 'typeset -p foo[10] has side effect'

unset foo
exp='typeset -a foo=((11 22) (66) )'
x=$(
	typeset -a foo=( ( 11 22 ) ( 44 55 ) )
	foo[1]=(66)
	typeset -p foo
) 2> /dev/null
[[ $x == "$exp" ]] || err_exit 'setting element 1 to index fooay failed'
unset foo
exp='typeset -a foo=((11 22) (x=3))'
x=$(
	typeset -a foo=( ( 11 22 ) ( 44 55 ) )
	foo[1]=(x=3)
	typeset -p foo
) 2> /dev/null
[[ $x == "$exp" ]] || err_exit 'setting element 1 of array to compound variable failed'

#test for cloning a very large index array - can core dump
(	
    trap 'x=$?;exit $(( $x!=0 ))' EXIT
    $SHELL <<- \EOF
	(
		print '('
		integer i
		for ((i=0 ; i < 16384 ; i++ )) ; do
                	printf '\tinteger var%i=%i\n' i i
        	done
        	printf 'typeset -a ar=(\n'
		for ((i=0 ; i < 16384 ; i++ )) ; do
			printf '\t[%d]=%d\n' i i
		done
		print ')'
		print ')'
	) | read -C hugecpv
	compound hugecpv2=hugecpv
	v=$(typeset -p hugecpv)
	[[ ${v/hugecpv/hugecpv2} == "$(typeset -p hugecpv2)" ]]
EOF
) 2> /dev/null || err_exit 'copying a large array fails'

unset foo
typeset -a foo
foo+=(bar)
[[ ${foo[0]} == bar ]] || 'appending to empty array not working'

unset isnull
typeset -A isnull
isnull[mdapp]=Y
: ${isnull[@]}
isnull[mdapp]=N
[[ ${isnull[*]} != *N* ]] && err_exit 'bug after ${arr[@]} with one element associative array'

unset arr2
arr2=()
typeset -A arr2
unset arr2
[[ $(typeset -p arr2) ]] && err_exit 'unset associative array of compound variables not working'

arr3=(x=3)
typeset -A arr3
[[  $(typeset -p arr3) == 'typeset -A arr3=()' ]] || err_exit 'typeset -A does not first unset compound variable.'

arr4=(x=3)
typeset -a arr4
[[  $(typeset -p arr4) == 'typeset -a arr4' ]] || err_exit 'typeset -a does not first unset compound variable.'

alias foo=bar
arr5=(foo bar)
[[ $(typeset -p arr5) == 'typeset -a arr5=(foo bar)' ]] || err_exit 'typeset expanding non-declaration aliases'

typeset -A Foo
Foo=( [a]=AA;[b]=BB)
[[ ${Foo[a]} == AA ]] || err_exit 'Fooa[a] is {Foo[a]} not AA' 

exit $((Errors<125?Errors:125))
