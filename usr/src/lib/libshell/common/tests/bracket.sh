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
null=''
if	[[ ! -z $null ]]
then	err_exit "-z: null string should be of zero length"
fi
file=/tmp/regress$$
if	[[ -z $file ]]
then	err_exit "-z: $file string should not be of zero length"
fi
trap "rm -f $file" EXIT
rm -f $file
if	[[ -a $file ]]
then	err_exit "-a: $file shouldn't exist"
fi
> $file
if	[[ ! -a $file ]]
then	err_exit "-a: $file should exist"
fi
chmod 777 $file
if	[[ ! -r $file ]]
then	err_exit "-r: $file should be readable"
fi
if	[[ ! -w $file ]]
then	err_exit "-w: $file should be writable"
fi
if	[[ ! -w $file ]]
then	err_exit "-x: $file should be executable"
fi
if	[[ ! -w $file || ! -r $file ]]
then	err_exit "-rw: $file should be readable/writable"
fi
if	[[ -s $file ]]
then	err_exit "-s: $file should be of zero size"
fi
if	[[ ! -f $file ]]
then	err_exit "-f: $file should be an ordinary file"
fi
if	[[  -d $file ]]
then	err_exit "-f: $file should not be a directory file"
fi
if	[[  ! -d . ]]
then	err_exit "-d: . should not be a directory file"
fi
if	[[  -f /dev/null ]]
then	err_exit "-f: /dev/null  should not be an ordinary file"
fi
chmod 000 $file
if	[[ -r $file ]]
then	err_exit "-r: $file should not be readable"
fi
if	[[ ! -O $file ]]
then	err_exit "-r: $file should be owned by me"
fi
if	[[ -w $file ]]
then	err_exit "-w: $file should not be writable"
fi
if	[[ -w $file ]]
then	err_exit "-x: $file should not be executable"
fi
if	[[ -w $file || -r $file ]]
then	err_exit "-rw: $file should not be readable/writable"
fi
if	[[   -z x &&  -z x || ! -z x ]]
then	:
else	err_exit " wrong precedence"
fi
if	[[   -z x &&  (-z x || ! -z x) ]]
then	err_exit " () grouping not working"
fi
if	[[ foo < bar ]]
then	err_exit "foo comes before bar"
fi
[[ . -ef $(pwd) ]] || err_exit ". is not $PWD"
set -o allexport
[[ -o allexport ]] || err_exit '-o: did not set allexport option'
if	[[ -n  $null ]]
then	err_exit "'$null' has non-zero length"
fi
if	[[ ! -r /dev/fd/0 ]]
then	err_exit "/dev/fd/0 not open for reading"
fi
if	[[ ! -w /dev/fd/2 ]]
then	err_exit "/dev/fd/2 not open for writing"
fi
sleep 1
if	[[ ! . -ot $file ]]
then	err_exit ". should be older than $file"
fi
if	[[ /bin -nt $file ]]
then	err_exit "$file should be newer than /bin"
fi
if	[[ $file != /tmp/* ]]
then	err_exit "$file should match /tmp/*"
fi
if	[[ $file = '/tmp/*' ]]
then	err_exit "$file should not equal /tmp/*"
fi
[[ ! ( ! -z $null && ! -z x) ]]	|| err_exit "negation and grouping"
[[ -z '' || -z '' || -z '' ]]	|| err_exit "three ors not working"
[[ -z '' &&  -z '' && -z '' ]]	|| err_exit "three ors not working"
(exit 8)
if	[[ $? -ne 8 || $? -ne 8 ]]
then	err_exit 'value $? within [[...]]'
fi
x='(x'
if	[[ '(x' != '('* ]]
then	err_exit " '(x' does not match '('* within [[...]]"
fi
if	[[ '(x' != "("* ]]
then	err_exit ' "(x" does not match "("* within [[...]]'
fi
if	[[ '(x' != \(* ]]
then	err_exit ' "(x" does not match \(* within [[...]]'
fi
if	[[ 'x(' != *'(' ]]
then	err_exit " 'x(' does not match '('* within [[...]]"
fi
if	[[ 'x&' != *'&' ]]
then	err_exit " 'x&' does not match '&'* within [[...]]"
fi
if	[[ 'xy' = *'*' ]]
then	err_exit " 'xy' matches *'*' within [[...]]"
fi
if	[[ 3 > 4 ]]
then	err_exit '3 < 4'
fi
if	[[ 4 < 3 ]]
then	err_exit '3 > 4'
fi
if	[[ 3x > 4x ]]
then	err_exit '3x < 4x'
fi
x='bin|dev|?'
cd /
if	[[ $(print $x) != "$x" ]]
then	err_exit 'extended pattern matching on command arguments'
fi
if	[[ dev != $x ]]
then	err_exit 'extended pattern matching not working on variables'
fi
if	[[ -u $SHELL ]]
then	err_exit "setuid on $SHELL"
fi
if	[[ -g $SHELL ]]
then	err_exit "setgid on $SHELL"
fi
test -d .  -a '(' ! -f . ')' || err_exit 'test not working'
if	[[ '!' != ! ]]
then	err_exit 'quoting unary operator not working'
fi
chmod 600 $file
exec 4> $file
print -u4 foobar
if	[[ ! -s $file ]]
then	err_exit "-s: $file should be non-zero"
fi
exec 4>&-
if	[[ 011 -ne 11 ]]
then	err_exit "leading zeros in arithmetic compares not ignored"
fi
{
	set -x
	[[ foo > bar ]]
} 2> /dev/null || { set +x; err_exit "foo<bar with -x enabled" ;}
set +x
(
	eval "[[ (a) ]]"
) 2> /dev/null || err_exit "[[ (a) ]] not working"
> $file
chmod 4755 "$file"
if	test -u $file && test ! -u $file
then	err_exit "test ! -u suidfile not working"
fi
for i in '(' ')' '[' ']'
do	[[ $i == $i ]] || err_exit "[[ $i != $i ]]"
done
(
	[[ aaaa == {4}(a) ]] || err_exit 'aaaa != {4}(a)'
	[[ aaaa == {2,5}(a) ]] || err_exit 'aaaa != {2,4}(a)'
	[[ abcdcdabcd == {3,6}(ab|cd) ]] || err_exit 'abcdcdabcd == {3,4}(ab|cd)'
	[[ abcdcdabcde == {5}(ab|cd)e ]] || err_exit 'abcdcdabcd == {5}(ab|cd)e'
) || err_exit 'Errors with {..}(...) patterns'
[[ D290.2003.02.16.temp == D290.+(2003.02.16).temp* ]] || err_exit 'pattern match bug with +(...)'
rm -rf $file
{
[[ -N $file ]] && err_exit 'test -N /tmp/*: st_mtime>st_atime after creat'
sleep 2
print 'hello world'
[[ -N $file ]] || err_exit 'test -N /tmp/*: st_mtime<=st_atime after write'
sleep 2
read
[[ -N $file ]] && err_exit 'test -N /tmp/*: st_mtime>st_atime after read'
} > $file < $file
if	rm -rf "$file" && ln -s / "$file"
then	[[ -L "$file" ]] || err_exit '-L not working'
	[[ -L "$file"/ ]] && err_exit '-L with file/ not working'
fi
$SHELL -c 't=1234567890; [[ $t == @({10}(\d)) ]]' 2> /dev/null || err_exit ' @({10}(\d)) pattern not working'
$SHELL -c '[[ att_ == ~(E)(att|cus)_.* ]]' 2> /dev/null || err_exit ' ~(E)(att|cus)_* pattern not working'
$SHELL -c '[[ att_ =~ (att|cus)_.* ]]' 2> /dev/null || err_exit ' =~ ere not working'
$SHELL -c '[[ abc =~ a(b)c ]]' 2> /dev/null || err_exit '[[ abc =~ a(b)c ]] fails'
$SHELL -xc '[[ abc =~  \babc\b ]]' 2> /dev/null || err_exit '[[ abc =~ \babc\b ]] fails'
[[ abc == ~(E)\babc\b ]] || err_exit '\b not preserved for ere when not in ()'
[[ abc == ~(iEi)\babc\b ]] || err_exit '\b not preserved for ~(iEi) when not in ()'
exit $((Errors))
