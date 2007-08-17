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
	((errors++))
}
alias err_exit='err_exit $LINENO'

integer aware=0 contrary=0 ignorant=0

function test_glob
{
	typeset lineno expected drop arg got sep op val add del
	if	[[ $1 == --* ]]
	then	del=${1#--}
		shift
	fi
	if	[[ $1 == ++* ]]
	then	add=${1#++}
		shift
	fi
	lineno=$1 expected=$2
	shift 2
	if	(( contrary ))
	then	if	[[ $expected == "<Beware> "* ]]
		then	expected=${expected#"<Beware> "}
			expected="$expected <Beware>"
		fi
		if	[[ $expected == *"<aXb> <abd>"* ]]
		then	expected=${expected/"<aXb> <abd>"/"<abd> <aXb>"}
		fi
	fi
	for arg
	do	got="$got$sep<$arg>"
		sep=" "
	done
	if	(( ignorant && aware ))
	then	if	[[ $del ]]
		then	got="<$del> $got"
		fi
		if	[[ $add ]]
		then	expected="<$add> $expected"
		fi
	fi
	if	[[ $got != "$expected" ]]
	then	err_exit $lineno "glob: got '$got' expected '$expected'"
	fi
}

function test_case
{
	typeset lineno expected subject pattern got
	lineno=$1 expected=$2 subject=$3 pattern=$4
	eval "
		case $subject in
		$pattern)	got='<match>' ;;
		*)		got='<nomatch>' ;;
		esac
	"
	if	[[ $got != "$expected" ]]
	then	err_exit $lineno "case $subject in $pattern) got '$got' expected '$expected'"
	fi
}

Command=${0##*/}
tmp=/tmp/ksh$$
integer errors=0
unset undefined

export LC_COLLATE=C

mkdir $tmp || err_exit $LINENO "mkdir $tmp failed"
trap "cd /; rm -rf $tmp" EXIT
cd $tmp || err_exit $LINENO "cd $tmp failed"
rm -rf *

touch B b
set -- *
case $* in
'b B')	contrary=1 ;;
b|B)	ignorant=1 ;;
esac
set -- $(/bin/sh -c 'echo [a-c]')
case $* in
B)	aware=1 ;;
esac
rm -rf *

touch a b c d abc abd abe bb bcd ca cb dd de Beware
mkdir bdir

test_glob $LINENO '<a> <abc> <abd> <abe> <X*>' a* X*
test_glob $LINENO '<a> <abc> <abd> <abe>' \a*

if	( set --nullglob ) 2>/dev/null
then
	set --nullglob

	test_glob $LINENO '<a> <abc> <abd> <abe>' a* X*

	set --nonullglob
fi

if	( set --failglob ) 2>/dev/null
then
	set --failglob
	mkdir tmp
	touch tmp/l1 tmp/l2 tmp/l3

	test_glob $LINENO '' tmp/l[12] tmp/*4 tmp/*3
	test_glob $LINENO '' tmp/l[12] tmp/*4 tmp/*3

	rm -r tmp
	set --nofailglob
fi

test_glob $LINENO '<bdir/>' b*/
test_glob $LINENO '<*>' \*
test_glob $LINENO '<a*>' 'a*'
test_glob $LINENO '<a*>' a\*
test_glob $LINENO '<c> <ca> <cb> <a*> <*q*>' c* a\* *q*
test_glob $LINENO '<**>' "*"*
test_glob $LINENO '<**>' \**
test_glob $LINENO '<\.\./*/>' "\.\./*/"
test_glob $LINENO '<s/\..*//>' 's/\..*//'
test_glob $LINENO '</^root:/{s/^[!:]*:[!:]*:\([!:]*\).*$/\1/>' "/^root:/{s/^[!:]*:[!:]*:\([!:]*\).*"'$'"/\1/"
test_glob $LINENO '<abc> <abd> <abe> <bb> <cb>' [a-c]b*
test_glob ++Beware $LINENO '<abd> <abe> <bb> <bcd> <bdir> <ca> <cb> <dd> <de>' [a-y]*[!c]
test_glob $LINENO '<abd> <abe>' a*[!c]

touch a-b aXb

test_glob $LINENO '<a-b> <aXb>' a[X-]b

touch .x .y

test_glob --Beware $LINENO '<Beware> <d> <dd> <de>' [!a-c]*

if	mkdir a\*b 2>/dev/null
then
	touch a\*b/ooo

	test_glob $LINENO '<a*b/ooo>' a\*b/*
	test_glob $LINENO '<a*b/ooo>' a\*?/*
	test_case $LINENO '<match>' '!7' '*\!*'
	test_case $LINENO '<match>' 'r.*' '*.\*'
	test_glob $LINENO '<abc>' a[b]c
	test_glob $LINENO '<abc>' a["b"]c
	test_glob $LINENO '<abc>' a[\b]c
	test_glob $LINENO '<abc>' a?c
	test_case $LINENO '<match>' 'abc' 'a"b"c'
	test_case $LINENO '<match>' 'abc' 'a*c'
	test_case $LINENO '<nomatch>' 'abc' '"a?c"'
	test_case $LINENO '<nomatch>' 'abc' 'a\*c'
	test_case $LINENO '<nomatch>' 'abc' 'a\[b]c'
	test_case $LINENO '<match>' '"$undefined"' '""'
	test_case $LINENO '<match>' 'abc' 'a["\b"]c'

	rm -rf mkdir a\*b
fi

mkdir man
mkdir man/man1
touch man/man1/sh.1

test_glob $LINENO '<man/man1/sh.1>' */man*/sh.*
test_glob $LINENO '<man/man1/sh.1>' $(echo */man*/sh.*)
test_glob $LINENO '<man/man1/sh.1>' "$(echo */man*/sh.*)"

test_case $LINENO '<match>' 'abc' 'a***c'
test_case $LINENO '<match>' 'abc' 'a*****?c'
test_case $LINENO '<match>' 'abc' '?*****??'
test_case $LINENO '<match>' 'abc' '*****??'
test_case $LINENO '<match>' 'abc' '*****??c'
test_case $LINENO '<match>' 'abc' '?*****?c'
test_case $LINENO '<match>' 'abc' '?***?****c'
test_case $LINENO '<match>' 'abc' '?***?****?'
test_case $LINENO '<match>' 'abc' '?***?****'
test_case $LINENO '<match>' 'abc' '*******c'
test_case $LINENO '<match>' 'abc' '*******?'
test_case $LINENO '<match>' 'abcdecdhjk' 'a*cd**?**??k'
test_case $LINENO '<match>' 'abcdecdhjk' 'a**?**cd**?**??k'
test_case $LINENO '<match>' 'abcdecdhjk' 'a**?**cd**?**??k***'
test_case $LINENO '<match>' 'abcdecdhjk' 'a**?**cd**?**??***k'
test_case $LINENO '<match>' 'abcdecdhjk' 'a**?**cd**?**??***k**'
test_case $LINENO '<match>' 'abcdecdhjk' 'a****c**?**??*****'
test_case $LINENO '<match>' "'-'" '[-abc]'
test_case $LINENO '<match>' "'-'" '[abc-]'
test_case $LINENO '<match>' "'\\'" '\\'
test_case $LINENO '<match>' "'\\'" '[\\]'
test_case $LINENO '<match>' "'\\'" "'\\'"
test_case $LINENO '<match>' "'['" '[[]'
test_case $LINENO '<match>' '[' '[[]'
test_case $LINENO '<match>' "'['" '['
test_case $LINENO '<match>' '[' '['
test_case $LINENO '<match>' "'[abc'" "'['*"
test_case $LINENO '<nomatch>' "'[abc'" '[*'
test_case $LINENO '<match>' '[abc' "'['*"
test_case $LINENO '<nomatch>' '[abc' '[*'
test_case $LINENO '<match>' 'abd' "a[b/c]d"
test_case $LINENO '<match>' 'a/d' "a[b/c]d"
test_case $LINENO '<match>' 'acd' "a[b/c]d"
test_case $LINENO '<match>' "']'" '[]]'
test_case $LINENO '<match>' "'-'" '[]-]'
test_case $LINENO '<match>' 'p' '[a-\z]'
test_case $LINENO '<match>' '"/tmp"' '[/\\]*'
test_case $LINENO '<nomatch>' 'abc' '??**********?****?'
test_case $LINENO '<nomatch>' 'abc' '??**********?****c'
test_case $LINENO '<nomatch>' 'abc' '?************c****?****'
test_case $LINENO '<nomatch>' 'abc' '*c*?**'
test_case $LINENO '<nomatch>' 'abc' 'a*****c*?**'
test_case $LINENO '<nomatch>' 'abc' 'a********???*******'
test_case $LINENO '<nomatch>' "'a'" '[]'
test_case $LINENO '<nomatch>' 'a' '[]'
test_case $LINENO '<nomatch>' "'['" '[abc'
test_case $LINENO '<nomatch>' '[' '[abc'

test_glob ++Beware $LINENO '<b> <bb> <bcd> <bdir>' b*
test_glob $LINENO '<Beware> <b> <bb> <bcd> <bdir>' [bB]*

if	( set --nocaseglob ) 2>/dev/null
then
	set --nocaseglob

	test_glob $LINENO '<Beware> <b> <bb> <bcd> <bdir>' b*
	test_glob $LINENO '<Beware> <b> <bb> <bcd> <bdir>' [b]*
	test_glob $LINENO '<Beware> <b> <bb> <bcd> <bdir>' [bB]*

	set --nonocaseglob
fi

if	( set -f ) 2>/dev/null
then
	set -f

	test_glob $LINENO '<*>' *

	set +f
fi

if	( set --noglob ) 2>/dev/null
then
	set --noglob

	test_glob $LINENO '<*>' *

	set --glob
fi

FIGNORE='.*|*'
test_glob $LINENO '<*>' *

FIGNORE='.*|*c|*e|?'
test_glob $LINENO '<a-b> <aXb> <abd> <bb> <bcd> <bdir> <ca> <cb> <dd> <man>' *

FIGNORE='.*|*b|*d|?'
test_glob $LINENO '<Beware> <abc> <abe> <bdir> <ca> <de> <man>' *

FIGNORE=
test_glob $LINENO '<man/man1/sh.1>' */man*/sh.*

unset FIGNORE
test_glob $LINENO '<bb> <ca> <cb> <dd> <de>' ??
test_glob $LINENO '<man/man1/sh.1>' */man*/sh.*

GLOBIGNORE='.*:*'
set -- *
if	[[ $1 == '*' ]]
then
	GLOBIGNORE='.*:*c:*e:?'
	test_glob $LINENO '<>' *

	GLOBIGNORE='.*:*b:*d:?'
	test_glob $LINENO '<>' *

	unset GLOBIGNORE
	test_glob $LINENO '<>' *
	test_glob $LINENO '<man/man1/sh.1>' */man*/sh.*

	GLOBIGNORE=
	test_glob $LINENO '<man/man1/sh.1>' */man*/sh.*
fi

exit $errors
