########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
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
	(( Errors++ ))
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0
if	[[ 'hi there' != "hi there" ]]
then	err_exit "single quotes not the same as double quotes"
fi
x='hi there'
if	[[ $x != 'hi there' ]]
then	err_exit "$x not the same as 'hi there'"
fi
if	[[ $x != "hi there" ]]
then	err_exit "$x not the same as \"hi there \""
fi
if	[[ \a\b\c\*\|\"\ \\ != 'abc*|" \' ]]
then	err_exit " \\ differs from '' "
fi
if	[[ "ab\'\"\$(" != 'ab\'\''"$(' ]]
then	err_exit " \"\" differs from '' "
fi
if	[[ $(print -r - 'abc*|" \') !=  'abc*|" \' ]]
then	err_exit "\$(print -r - '') differs from ''"
fi
if	[[ $(print -r - "abc*|\" \\") !=  'abc*|" \' ]]
then	err_exit "\$(print -r - '') differs from ''"
fi
if	[[ "$(print -r - 'abc*|" \')" !=  'abc*|" \' ]]
then	err_exit "\"\$(print -r - '')\" differs from ''"
fi
if	[[ "$(print -r - "abc*|\" \\")" !=  'abc*|" \' ]]
then	err_exit "\"\$(print -r - "")\" differs from ''"
fi
if	[[ $(print -r - $(print -r - 'abc*|" \')) !=  'abc*|" \' ]]
then	err_exit "nested \$(print -r - '') differs from ''"
fi
if	[[ "$(print -r - $(print -r - 'abc*|" \'))" !=  'abc*|" \' ]]
then	err_exit "\"nested \$(print -r - '')\" differs from ''"
fi
if	[[ $(print -r - "$(print -r - 'abc*|" \')") !=  'abc*|" \' ]]
then	err_exit "nested \"\$(print -r - '')\" differs from ''"
fi
unset x
if	[[ ${x-$(print -r - "abc*|\" \\")} !=  'abc*|" \' ]]
then	err_exit "\${x-\$(print -r - '')} differs from ''"
fi
if	[[ ${x-$(print -r - "a}c*|\" \\")} !=  'a}c*|" \' ]]
then	err_exit "\${x-\$(print -r - '}')} differs from ''"
fi
x=$((echo foo)|(cat))
if	[[ $x != foo  ]]
then	err_exit "((cmd)|(cmd)) failed"
fi
x=$(print -r -- "\"$HOME\"")
if	[[ $x != '"'$HOME'"' ]]
then	err_exit "nested double quotes failed"
fi
unset z
: ${z="a{b}c"}
if	[[ $z != 'a{b}c' ]]
then	err_exit '${z="a{b}c"} not correct'
fi
unset z
: "${z="a{b}c"}"
if	[[ $z != 'a{b}c' ]]
then	err_exit '"${z="a{b}c"}" not correct'
fi
if	[[ $(print -r -- "a\*b") !=  'a\*b' ]]
then	err_exit '$(print -r -- "a\*b") differs from  a\*b'
fi
unset x
if	[[ $(print -r -- "a\*b$x") !=  'a\*b' ]]
then	err_exit '$(print -r -- "a\*b$x") differs from  a\*b'
fi
x=hello
set -- ${x+foo bar bam}
if	(( $# !=3 ))
then	err_exit '${x+foo bar bam} does not yield three arguments'
fi
set -- ${x+foo "bar bam"}
if	(( $# !=2 ))
then	err_exit '${x+foo "bar bam"} does not yield two arguments'
fi
set -- ${x+foo 'bar bam'}
if	(( $# !=2 ))
then	err_exit '${x+foo '\''bar bam'\''} does not yield two arguments'
fi
set -- ${x+foo $x bam}
if	(( $# !=3 ))
then	err_exit '${x+foo $x bam} does not yield three arguments'
fi
set -- ${x+foo "$x" bam}
if	(( $# !=3 ))
then	err_exit '${x+foo "$x" bam} does not yield three arguments'
fi
set -- ${x+"foo $x bam"}
if	(( $# !=1 ))
then	err_exit '${x+"foo $x bam"} does not yield one argument'
fi
set -- "${x+foo $x bam}"
if	(( $# !=1 ))
then	err_exit '"${x+foo $x bam}" does not yield one argument'
fi
set -- ${x+foo "$x "bam}
if	(( $# !=2 ))
then	err_exit '${x+foo "$x "bam} does not yield two arguments'
fi
x="ab$'cd"
if	[[ $x != 'ab$'"'cd" ]]
then	err_exit '$'"' inside double quotes not working"
fi
x=`print 'ab$'`
if	[[ $x != 'ab$' ]]
then	err_exit '$'"' inside `` quotes not working"
fi
unset a
x=$(print -r -- "'\
\
")
if	[[ $x != "'" ]]
then	err_exit 'line continuation in double strings not working'
fi
x=$(print -r -- "'\
$a\
")
if	[[ $x != "'" ]]
then	err_exit 'line continuation in expanded double strings not working'
fi
x='\*'
if	[[ $(print -r -- $x) != '\*' ]]
then	err_exit 'x="\\*";$x != \*'
fi
x='   hello    world    '
set -- $x
if	(( $# != 2 ))
then	err_exit 'field splitting error'
fi
x=$(print -r -- '1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890 \
1234567890123456789012345678901234567890123456789012345678901234567890')
if	(( ${#x} != (15*73-3) ))
then	err_exit "length of x, ${#x}, is incorrect should be $((15*73-3))"
fi
x='$hi'
if	[[ $x\$ != '$hi$' ]]
then	err_exit ' $x\$, with x=$hi, does not expand to $hi$'
fi
if	[[ $x$ != '$hi$' ]]
then	err_exit ' $x$, with x=$hi, does not expand to $hi$'
fi
set -- $(/bin/echo foo;sleep 1;/bin/echo bar)
if	[[ $# != 2 ]]
then	err_exit 'word splitting after command substitution not working'
fi
unset q
if	[[ "${q:+'}q${q:+'}" != q ]]
then	err_exit 'expansion of "{q:+'\''}" not correct when q unset'
fi
q=1
if	[[ "${q:+'}q${q:+'}" != "'q'" ]]
then	err_exit 'expansion of "{q:+'\''}" not correct when q set'
fi
x=$'x\' #y'
if	[[ $x != "x' #y" ]]
then	err_exit "$'x\' #y'" not working
fi
x=$q$'x\' #y'
if	[[ $x != "1x' #y" ]]
then	err_exit "$q$'x\' #y'" not working
fi
IFS=,
x='a,b\,c,d'
set -- $x
if	[[ $2 != 'b\' ]]
then	err_exit "field splitting of $x with IFS=$IFS not working"
fi
foo=bar
bar=$(print -r -- ${foo+\\n\ })
if	[[ $bar != '\n ' ]]
then	err_exit '${foo+\\n\ } expansion error'
fi
unset bar
bar=$(print -r -- ${foo+\\n\ $bar})
if	[[ $bar != '\n ' ]]
then	err_exit '${foo+\\n\ $bar} expansion error with bar unset'
fi
x='\\(..\\)|&\|\|\\&\\|'
if	[[ $(print -r -- $x) != "$x" ]]
then	err_exit '$x, where x=\\(..\\)|&\|\|\\&\\| not working'
fi
x='\\('
if	[[ $(print -r -- a${x}b) != a"${x}"b ]]
then	err_exit 'a${x}b, where x=\\( not working'
fi
x=
if	[[ $(print -r -- $x'\\1') != '\\1' ]]
then	err_exit 'backreference inside single quotes broken'
fi
set -- ''
set -- "$@"
if	(( $# != 1 ))
then	err_exit '"$@" not preserving nulls'
fi
x=
if	[[ $(print -r s"!\2${x}\1\a!") != 's!\2\1\a!' ]]
then	err_exit  'print -r s"!\2${x}\1\a!" not equal s!\2\1\a!'
fi
if	[[ $(print -r $'foo\n\n\n') != foo ]]
then	err_exit 'trailing newlines on comsubstitution not removed'
fi
unset x
if	[[ ${x:='//'} != '//' ]]
then	err_exit '${x:='//'} != "//"'
fi
if	[[ $(print -r "\"hi$\"")	!= '"hi$"' ]]
then	err_exit '$\ not correct inside ""'
fi
unset x
if	[[ "${x-a\}b}" != 'a}b' ]]
then	err_exit '"${x-a\}b}" !=  "a}b"'
fi
if	[[ "\}\]$x\*\{\[\\" != '\}\]\*\{\[\' ]]
then	err_exit '"\}\]$x\*\{\[\\" !=  "\}\]\*\{\[\"'
fi
foo=yes
if	[[ $(print -r -- {\$foo}) != '{$foo}' ]]
then	err_exit '{\$foo}' not expanded correctly
fi
[[ foo == $(
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
###########################################################
print foo) ]] || err_exit "command subsitution with long comments broken"
subject='some/other/words'
re='@(?*)/@(?*)/@(?*)'
[[ ${subject/${re}/\3} != words ]] && err_exit 'string replacement with \3 not working'
[[ ${subject/${re}/'\3'} != '\3' ]] && err_exit 'string replacement with '"'\3'"' not working'
[[ ${subject/${re}/"\\3"} != '\3' ]] && err_exit 'string replacement with "\\3" not working'
[[ ${subject/${re}/"\3"} != '\3' ]] && err_exit 'string replacement with "\3" not working'
string='\3'
[[ ${subject/${re}/${string}} != words ]] && err_exit 'string replacement with $string not working with string=\3'
[[ $(print -r "${subject/${re}/${string}}") != words ]] && err_exit 'string replacement with $string not working with string=\3 using print'
[[ ${subject/${re}/"${string}"} != '\3' ]] && err_exit 'string replacement with "$string" not working with  string=\3'
[[ $(print -r "${subject/${re}/"${string}"}") != '\3' ]] && err_exit 'string replacement with "$string" not working with  string=\3 using print'
string='\\3'
[[ ${subject/${re}/${string}} != '\3' ]] && err_exit 'string replacement with $string not working with string=\\3'
[[ ${subject/${re}/"${string}"} != '\\3' ]] && err_exit 'string replacement with "$string" not working with  string=\\3'
[[ ${subject/${re}/\4} != '\4' ]] && err_exit 'string replacement with \4 not working'
[[ ${subject/${re}/'\4'} != '\4' ]] && err_exit 'string replacement with '\4' not working'
string='\4'
[[ ${subject/${re}/${string}} != '\4' ]] && err_exit 'string replacement with $string not working with string=\4'
[[ ${subject/${re}/"${string}"} != '\4' ]] && err_exit 'string replacement with "$string" not working with  string=\4'
string='&foo'
[[ ${subject/${re}/${string}} != '&foo' ]] && err_exit 'string replacement with $string not working with string=&foo'
[[ ${subject/${re}/"${string}"} != '&foo' ]] && err_exit 'string replacement with "$string" not working with  string=&foo'
{
x=x
x=${x:-`id | sed 's/^[^(]*(\([^)]*\)).*/\1/'`}
} 2> /dev/null || err_exit 'skipping over `` failed'
[[ $x == x ]] || err_exit 'assignment ${x:=`...`} failed'
[[ $($SHELL -c 'print a[') == 'a[' ]] || err_exit "unbalanced '[' in command arg fails"
$SHELL -c $'false && (( `wc -l /dev/null | nawk \'{print $1}\'` > 2 )) && true;:' 2> /dev/null ||  err_exit 'syntax error with ` in arithmetic expression'
{ $SHELL  -c '((  1`: "{ }"` ))' ;} 2> /dev/null || err_exit 'problem with ` inside (())'
varname=foobarx
x=`print '"\$'${varname}'"'`
[[ $x == '"$foobarx"' ]] ||  err_exit $'\\$\' not handled correctly inside ``'

copy1=5 copynum=1
foo="`eval echo "$"{copy$copynum"-0}"`"
[[ $foo == "$copy1" ]] || err_exit '$"..." not being ignored inside ``'

[[ $($SHELL -c 'set --  ${1+"$@"}; print $#' cmd '') == 1 ]] || err_exit '${1+"$@"} with one empty argument fails'
[[ $($SHELL -c 'set --  ${1+"$@"}; print $#' cmd foo '') == 2 ]] || err_exit '${1+"$@"} with one non-empty and on empty argument fails'
[[ $($SHELL -c 'set --  ${1+"$@"}; print $#' cmd "" '') == 2 ]] || err_exit '${1+"$@"} with two empty arguments fails'
[[ $($SHELL -c 'set --  ${1+"$@"}; print $#' cmd "" '' '') == 3 ]] || err_exit '${1+"$@"} with three empty arguments fails'
[[ $($SHELL -c 'set --  "$@"; print $#' cmd '') == 1 ]] || err_exit '"$@" with one empty argument fails'
[[ $($SHELL -c 'set --  "${@:2}"; print $#' cmd '') == 0 ]] || err_exit '"$@" with one empty argument fails'
[[ $($SHELL -c 'set --  "$@"; print $#' cmd foo '') == 2 ]] || err_exit '"$@" with one non-empty and on empty argument fails'
[[ $($SHELL -c 'set --  "$@"; print $#' cmd "" '') == 2 ]] || err_exit '"$@" with two empty arguments fails'
[[ $($SHELL -c 'set --  "$@"; print $#' cmd "" '' '') == 3 ]] || err_exit '"$@" with three empty arguments fails'
args=('')
set -- "${args[@]}"
[[ $# == 1 ]] || err_exit '"${args[@]}"} with one empty argument fails'
set -- ${1+"${args[@]}"}
[[ $# == 1 ]] || err_exit '${1+"${args[@]}"} with one empty argument fails'
args=(foo '')
set -- "${args[@]}"
[[ $# == 2 ]] || err_exit '"${args[@]}"} with one non-empty and one empty argument fails'
set -- ${1+"${args[@]}"}
[[ $# == 2 ]] || err_exit '${1+"${args[@]}"} with one non-empty and one empty argument fails'

unset ARGS
set --
ARGS=("$@")
set -- "${ARGS[@]}"
(( $# )) &&  err_exit 'set -- "${ARGS[@]}" for empty array should not produce arguments'

exit $((Errors<125?Errors:125))
