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

unset LANG ${!LC_*}

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT
cd $tmp || exit

a=$($SHELL -c '/' 2>&1 | sed -e "s,.*: *,," -e "s, *\[.*,,")
b=$($SHELL -c '(LC_ALL=debug / 2>/dev/null); /' 2>&1 | sed -e "s,.*: *,," -e "s, *\[.*,,")
[[ "$b" == "$a" ]] || err_exit "locale not restored after subshell -- expected '$a', got '$b'"
b=$($SHELL -c '(LC_ALL=debug; / 2>/dev/null); /' 2>&1 | sed -e "s,.*: *,," -e "s, *\[.*,,")
[[ "$b" == "$a" ]] || err_exit "locale not restored after subshell -- expected '$a', got '$b'"

# test shift-jis \x81\x40 ... \x81\x7E encodings
# (shift char followed by 7 bit ascii)

typeset -i16 chr
for locale in $(PATH=/bin:/usr/bin locale -a 2>/dev/null | grep -i jis)
do	export LC_ALL=$locale
	for ((chr=0x40; chr<=0x7E; chr++))
	do	c=${chr#16#}
		for s in \\x81\\x$c \\x$c
		do	b="$(printf "$s")"
			eval n=\$\'$s\'
			[[ $b == "$n" ]] || err_exit "LC_ALL=$locale printf difference for \"$s\" -- expected '$n', got '$b'"
			u=$(print -- $b)
			q=$(print -- "$b")
			[[ $u == "$q" ]] || err_exit "LC_ALL=$locale quoted print difference for \"$s\" -- $b => '$u' vs \"$b\" => '$q'"
		done
	done
done

# this locale is supported by ast on all platforms
# EU for { decimal_point="," thousands_sep="." }

locale=C_EU.UTF-8

export LC_ALL=C

# test multibyte value/trace format -- $'\303\274' is UTF-8 u-umlaut

c=$(LC_ALL=C $SHELL -c "printf $':%2s:\n' $'\303\274'")
u=$(LC_ALL=$locale $SHELL -c "printf $':%2s:\n' $'\303\274'" 2>/dev/null)
if	[[ "$c" != "$u" ]]
then	LC_ALL=$locale
	x=$'+2+ typeset item.text\
+3+ item.text=\303\274\
+4+ print -- \303\274\
\303\274\
+5+ eval $\'arr[0]=(\\n\\ttext=\\303\\274\\n)\'
+2+ arr[0].text=ü\
+6+ print -- \303\274\
ü\
+7+ eval txt=$\'(\\n\\ttext=\\303\\274\\n)\'
+2+ txt.text=\303\274\
+8+ print -- \'(\' text=$\'\\303\\274\' \')\'\
( text=\303\274 )'
	u=$(LC_ALL=$locale PS4='+$LINENO+ ' $SHELL -x -c "
		item=(typeset text)
		item.text=$'\303\274'
		print -- \"\${item.text}\"
		eval \"arr[0]=\$item\"
		print -- \"\${arr[0].text}\"
		eval \"txt=\${arr[0]}\"
		print -- \$txt
	" 2>&1)
	[[ "$u" == "$x" ]] || err_exit LC_ALL=$locale multibyte value/trace format failed

	x=$'00fc\n20ac'
	u=$(LC_ALL=$locale $SHELL -c $'printf "%04x\n" \$\'\"\303\274\"\' \$\'\"\xE2\x82\xAC\"\'')
	[[ $u == $x ]] || err_exit LC_ALL=$locale multibyte %04x printf format failed
fi

if	(( $($SHELL -c $'export LC_ALL='$locale$'; print -r "\342\202\254\342\202\254\342\202\254\342\202\254w\342\202\254\342\202\254\342\202\254\342\202\254" | wc -m' 2>/dev/null) == 10 ))
then	LC_ALL=$locale $SHELL -c b1=$'"\342\202\254\342\202\254\342\202\254\342\202\254w\342\202\254\342\202\254\342\202\254\342\202\254"; [[ ${b1:4:1} == w ]]' || err_exit 'multibyte ${var:offset:len} not working correctly'
fi

#$SHELL -c 'export LANG='$locale'; printf "\u[20ac]\u[20ac]" > $tmp/two_euro_chars.txt'
printf $'\342\202\254\342\202\254' > $tmp/two_euro_chars.txt
exp="6 2 6"
set -- $($SHELL -c "
	unset LC_CTYPE
	export LANG=$locale
	export LC_ALL=C
	command wc -C < $tmp/two_euro_chars.txt
	unset LC_ALL
	command wc -C < $tmp/two_euro_chars.txt
	export LC_ALL=C
	command wc -C < $tmp/two_euro_chars.txt
")
got=$*
[[ $got == $exp ]] || err_exit "command wc LC_ALL default failed -- expected '$exp', got '$got'"
set -- $($SHELL -c "
	if	builtin wc 2>/dev/null || builtin -f cmd wc 2>/dev/null
	then	unset LC_CTYPE
		export LANG=$locale
		export LC_ALL=C
		wc -C < $tmp/two_euro_chars.txt
		unset LC_ALL
		wc -C < $tmp/two_euro_chars.txt
		export LC_ALL=C
		wc -C < $tmp/two_euro_chars.txt
	fi
")
got=$*
[[ $got == $exp ]] || err_exit "builtin wc LC_ALL default failed -- expected '$exp', got '$got'"

# multibyte char straddling buffer boundary

{
	unset i
	integer i
	for ((i = 0; i < 163; i++))
	do	print "#234567890123456789012345678901234567890123456789"
	done
	printf $'%-.*c\n' 15 '#'
	for ((i = 0; i < 2; i++))
	do	print $': "\xe5\xae\x9f\xe8\xa1\x8c\xe6\xa9\x9f\xe8\x83\xbd\xe3\x82\x92\xe8\xa1\xa8\xe7\xa4\xba\xe3\x81\x97\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82" :'
	done
} > ko.dat

LC_ALL=$locale $SHELL < ko.dat 2> /dev/null || err_exit "script with multibyte char straddling buffer boundary fails"

#	exp	LC_ALL		LC_NUMERIC	LANG
set -- \
	2,5	$locale		C		''		\
	2.5	C		$locale		''		\
	2,5	$locale		''		C		\
	2,5	''		$locale		C		\
	2.5	C		''		$locale		\
	2.5	''		C		$locale		\

unset a b c
unset LC_ALL LC_NUMERIC LANG
integer a b c
while	(( $# >= 4 ))
do	exp=$1
	unset H V
	typeset -A H
	typeset -a V
	[[ $2 ]] && V[0]="export LC_ALL=$2;"
	[[ $3 ]] && V[1]="export LC_NUMERIC=$3;"
	[[ $4 ]] && V[2]="export LANG=$4;"
	for ((a = 0; a < 3; a++))
	do	for ((b = 0; b < 3; b++))
		do	if	(( b != a ))
			then	for ((c = 0; c < 3; c++))
				do	if	(( c != a && c != b ))
					then	T=${V[$a]}${V[$b]}${V[$c]}
						if	[[ ! ${H[$T]} ]]
						then	H[$T]=1
							got=$($SHELL -c "${T}print \$(( $exp ))" 2>&1)
							[[ $got == $exp ]] || err_exit "${T} sequence failed -- expected '$exp', got '$got'"
						fi
					fi
				done
			fi
		done
	done
	shift 4
done

# setocale(LC_ALL,"") after setlocale() initialization

printf 'f1\357\274\240f2\n' > input1
printf 't2\357\274\240f1\n' > input2
printf '\357\274\240\n' > delim
print "export LC_ALL=$locale
join -j1 1 -j2 2 -o 1.1 -t \$(cat delim) input1 input2 > out" > script
$SHELL -c 'unset LANG ${!LC_*}; $SHELL ./script' ||
err_exit "join test script failed -- exit code $?"
exp="f1"
got="$(<out)"
[[ $got == "$exp" ]] || err_exit "LC_ALL test script failed -- expected '$exp', got '$got'"

# multibyte identifiers

exp=OK
got=$(LC_ALL=C.UTF-8 $SHELL -c $'\u[5929]=OK; print ${\u[5929]}' 2>&1)
[[ $got == "$exp" ]] || err_exit "multibyte variable definition/expansion failed -- expected '$exp', got '$got'"
got=$(LC_ALL=C.UTF-8 $SHELL -c $'function \u[5929]\n{\nprint OK;\n}; \u[5929]' 2>&1)
[[ $got == "$exp" ]] || err_exit "multibyte ksh function definition/execution failed -- expected '$exp', got '$got'"
got=$(LC_ALL=C.UTF-8 $SHELL -c $'\u[5929]()\n{\nprint OK;\n}; \u[5929]' 2>&1)
[[ $got == "$exp" ]] || err_exit "multibyte posix function definition/execution failed -- expected '$exp', got '$got'"

# this locale is supported by ast on all platforms
# mainly used to debug multibyte and message translation code
# however wctype is not supported but that's ok for these tests

locale=debug

if	[[ "$(LC_ALL=$locale $SHELL <<- \+EOF+
		x=a<1z>b<2yx>c
		print ${#x}
		+EOF+)" != 5
	]]
then	err_exit '${#x} not working with multibyte locales'
fi

dir=_not_found_
exp=2
for cmd in \
	"cd $dir; export LC_ALL=debug; cd $dir" \
	"cd $dir; LC_ALL=debug cd $dir" \

do	got=$($SHELL -c "$cmd" 2>&1 | sort -u | wc -l)
	(( ${got:-0} == $exp )) || err_exit "'$cmd' sequence failed -- error message not localized"
done
exp=121
for lc in LANG LC_MESSAGES LC_ALL
do	for cmd in "($lc=$locale;cd $dir)" "$lc=$locale;cd $dir;unset $lc" "function tst { typeset $lc=$locale;cd $dir; }; tst"
	do	tst="$lc=C;cd $dir;$cmd;cd $dir;:"
		$SHELL -c "unset LANG \${!LC_*}; $SHELL -c '$tst'" > out 2>&1 ||
		err_exit "'$tst' failed -- exit status $?"
		integer id=0
		unset msg
		typeset -A msg
		got=
		while	read -r line
		do	line=${line##*:}
			if	[[ ! ${msg[$line]} ]]
			then	msg[$line]=$((++id))
			fi
			got+=${msg[$line]}
		done < out
		[[ $got == $exp ]] || err_exit "'$tst' failed -- expected '$exp', got '$got'"
	done
done

exp=123
got=$(LC_ALL=debug $SHELL -c "a<2A@>z=$exp; print \$a<2A@>z")
[[ $got == $exp ]] || err_exit "multibyte debug locale \$a<2A@>z failed -- expected '$exp', got '$got'"

unset LC_ALL LC_MESSAGES
export LANG=debug
function message
{
        print -r $"An error occurred."
}
exp=$'(libshell,3,46)\nAn error occurred.\n(libshell,3,46)'
alt=$'(debug,message,libshell,An error occurred.)\nAn error occurred.\n(debug,message,libshell,An error occurred.)'
got=$(message; LANG=C message; message)
[[ $got == "$exp" || $got == "$alt" ]] || {
	EXP=$(printf %q "$exp")
	ALT=$(printf %q "$alt")
	GOT=$(printf %q "$got")
	err_exit "LANG change not seen by function -- expected $EXP or $ALT, got $GOT"
}

a_thing=fish
got=$(print -r aa$"\\ahello \" /\\${a_thing}/\\"zz)
exp='aa(debug,'$Command',libshell,\ahello " /\fish/\)zz'
[[ $got == "$exp" ]] || err_exit "$\"...\" containing expansions fails: expected $exp, got $got"

exp='(debug,'$Command',libshell,This is a string\n)'
typeset got=$"This is a string\n"
[[ $got == "$exp" ]] || err_exit "$\"...\" in assignment expansion fails: expected $exp got $got"

unset LANG

LC_ALL=C
x=$"hello"
[[ $x == hello ]] || err_exit 'assignment of message strings not working'

# tests for multibyte characteer at buffer boundary
{
	print 'cat << \\EOF'
	for ((i=1; i < 164; i++))
	do	print 123456789+123456789+123456789+123456789+123456789
	done 
	print $'next character is multibyte<2b|>c<3d|\>foo'
	for ((i=1; i < 10; i++))
	do	print 123456789+123456789+123456789+123456789+123456789
	done
	print EOF
} > script$$.1
chmod +x script$$.1
x=$(  LC_ALL=debug $SHELL ./script$$.1)
[[ ${#x} == 8641 ]] || err_exit 'here doc contains wrong number of chars with multibyte locale'
[[ $x == *$'next character is multibyte<2b|>c<3d|\>foo'* ]] || err_exit "here_doc doesn't contain line with multibyte chars"


x=$(LC_ALL=debug $SHELL -c 'x="a<2b|>c";print -r -- ${#x}')
(( x == 3  )) || err_exit 'character length of multibyte character should be 3'
x=$(LC_ALL=debug $SHELL -c 'typeset -R10 x="a<2b|>c";print -r -- "${x}"')
[[ $x == '   a<2b|>c' ]] || err_exit 'typeset -R10 should begin with three spaces'
x=$(LC_ALL=debug $SHELL -c 'typeset -L10 x="a<2b|>c";print -r -- "${x}"')
[[ $x == 'a<2b|>c   ' ]] || err_exit 'typeset -L10 should end in three spaces'

if      $SHELL -c "export LC_ALL=en_US.UTF-8; c=$'\342\202\254'; [[ \${#c} == 1 ]]" 2>/dev/null
then	LC_ALL=en_US.UTF-8
	unset i p1 p2 x
	for i in 9 b c d 20 1680 2000 2001 2002 2003 2004 2005 2006 2008 2009 200a 2028 2029 3000 # 1803 2007 202f  205f
	do	if	! eval "[[ \$'\\u[$i]' == [[:space:]] ]]"
		then	x+=,$i
		fi
	done
	if	[[ $x ]]
	then	if	[[ $x == ,*,* ]]
		then	p1=s p2="are not space characters"
		else	p1=  p2="is not a space character"
		fi
		err_exit "unicode char$p1 ${x#?} $p2 in locale $LC_ALL"
	fi
	unset x
	x=$(printf "hello\u[20ac]\xee world")
	[[ $(print -r -- "$x") == $'hello\u[20ac]\xee world' ]] || err_exit '%q with unicode and non-unicode not working'
	if	[[ $(whence od) ]]
	then	got='68 65 6c 6c 6f e2 82 ac ee 20 77 6f 72 6c 64 0a'
		[[ $(print -r -- "$x" | od -An -tx1 | xargs echo) == "$got" ]] || err_exit "incorrect string from printf %q"
	fi
	
fi

exit $((Errors<125?Errors:125))

