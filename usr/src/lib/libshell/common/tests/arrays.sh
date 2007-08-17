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

function fun
{
	integer i
	unset xxx
	for i in 0 1
	do	xxx[$i]=$i
	done
}

Command=${0##*/}
integer Errors=0
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
unset y
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
then	err_exit 'Error in subscript names'
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
trap 'rm -f /tmp/sharr$$' EXIT
print 'print ${var[0]} ${var[1]}' > /tmp/sharr$$
chmod +x /tmp/sharr$$
[[ $($SHELL -c "var=(foo bar);export var;/tmp/sharr$$") == foo ]] || err_exit 'export array not exporting just first element'
unset foo
set -o allexport
foo=one
foo[1]=two
foo[0]=three
[[ $foo == three ]] || err_exit 'export all not working with arrays'
cat > /tmp/sharr$$ <<- \!
	typeset -A foo
	print foo${foo[abc]}
!
# 04-05-24 bug fix
unset foo
[[ $($SHELL -c "typeset -A foo;/tmp/sharr$$")  == foo ]] 2> /dev/null || err_exit 'empty associative arrays not being cleared correctly before scripts'
[[ $($SHELL -c "typeset -A foo;foo[abc]=abc;/tmp/sharr$$") == foo ]] 2> /dev/null || err_exit 'associative arrays not being cleared correctly before scripts'
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
: ${_foo[bar=4]}
(( bar == 4 )) || err_exit 'subscript of unset variable not evaluated'
exit $((Errors))
