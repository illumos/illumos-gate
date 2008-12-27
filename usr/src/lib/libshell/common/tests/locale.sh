########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2008 AT&T Intellectual Property          #
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

# LC_ALL=debug is an ast specific debug/test locale

if	[[ "$(LC_ALL=debug $SHELL <<- \+EOF+
		x=a<1z>b<2yx>c
		print ${#x}
		+EOF+)" != 5
	]]
then	err_exit '${#x} not working with multibyte locales'
fi

export LC_ALL=C
if	(( $($SHELL -c $'export LC_ALL=en_US.UTF-8; print -r "\342\202\254\342\202\254\342\202\254\342\202\254w\342\202\254\342\202\254\342\202\254\342\202\254" | wc -m' 2>/dev/null) == 10 ))
then	LC_ALL=en_US.UTF-8 $SHELL -c b1=$'"\342\202\254\342\202\254\342\202\254\342\202\254w\342\202\254\342\202\254\342\202\254\342\202\254"; [[ ${b1:4:1} == w ]]' || err_exit 'Multibyte ${var:offset:len} not working correctly'
fi

export LC_ALL=C
a=$($SHELL -c '/' 2>&1 | sed -e "s,.*: *,," -e "s, *\[.*,,")
b=$($SHELL -c '(LC_ALL=debug / 2>/dev/null); /' 2>&1 | sed -e "s,.*: *,," -e "s, *\[.*,,")
[[ "$b" == "$a" ]] || err_exit "locale not restored after subshell -- expected '$a', got '$b'"
b=$($SHELL -c '(LC_ALL=debug; / 2>/dev/null); /' 2>&1 | sed -e "s,.*: *,," -e "s, *\[.*,,")
[[ "$b" == "$a" ]] || err_exit "locale not restored after subshell -- expected '$a', got '$b'"

# test shift-jis \x81\x40 ... \x81\x7E encodings
# (shift char followed by 7 bit ascii)

typeset -i16 chr
for lc_all in $(PATH=/bin:/usr/bin locale -a 2>/dev/null | grep -i jis)
do	export LC_ALL=$lc_all
	for ((chr=0x40; chr<=0x7E; chr++))
	do	c=${chr#16#}
		for s in \\x81\\x$c \\x$c
		do	b="$(printf "$s")"
			eval n=\$\'$s\'
			[[ $b == "$n" ]] || err_exit "LC_ALL=$lc_all printf difference for \"$s\" -- expected '$n', got '$b'"
			u=$(print -- $b)
			q=$(print -- "$b")
			[[ $u == "$q" ]] || err_exit "LC_ALL=$lc_all quoted print difference for \"$s\" -- $b => '$u' vs \"$b\" => '$q'"
		done
	done
done

# test multibyte value/trace format -- $'\303\274' is UTF-8 u-umlaut

LC_ALL=C
lc_all=de_DE.UTF-8
c=$(LC_ALL=C $SHELL -c "printf $':%2s:\n' $'\303\274'")
u=$(LC_ALL=$lc_all $SHELL -c "printf $':%2s:\n' $'\303\274'" 2>/dev/null)
if	[[ "$c" != "$u" ]]
then	LC_ALL=$lc_all
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
	u=$(LC_ALL=$lc_all PS4='+$LINENO+ ' $SHELL -x -c "
		item=(typeset text)
		item.text=$'\303\274'
		print -- \"\${item.text}\"
		eval \"arr[0]=\$item\"
		print -- \"\${arr[0].text}\"
		eval \"txt=\${arr[0]}\"
		print -- \$txt
	" 2>&1)
	[[ "$u" == "$x" ]] || err_exit LC_ALL=$lc_all multibyte value/trace format failed
fi

exit $Errors
