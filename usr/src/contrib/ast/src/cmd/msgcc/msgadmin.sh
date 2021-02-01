########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 2000-2011 AT&T Intellectual Property          #
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
#                 Glenn Fowler <gsf@research.att.com>                  #
#                                                                      #
########################################################################
: message catalog administration

command=msgadmin

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	ARGV0="-a $command"
	USAGE=$'
[-?
@(#)$Id: msgadmin (AT&T Labs Research) 2001-06-08 $
]
'$USAGE_LICENSE$'
[+NAME?'$command$' - message catalog file administration]
[+DESCRIPTION?\b'$command$'\b administers message catalog files. If no \afile\a
	operands are specified then all message files in the local
	\b$INSTALLROOT\b source tree are operated on. Exactly one of
	\b--generate\b, \b--remove\b, \b--translate\b, or \b--verify\b
	must be specified.]
[D:debug?Passed to \btranslate\b(1).]
[a:all?Passed to \btranslate\b(1).]
[c:cache?Passed to \btranslate\b(1).]
[d:dialect?Operate on the dialects in the \b,\b separated \adialect\a list.
	\b-\b means all dialects supported by \btranslate\b(1).]:[dialect:=-]
[f:force?Force binary catalog generation even when the current binary is newer
	than the source.]
[g:generate?Generate and install \bgencat\b(1) binary message catalogs.]
[l:list?List each installed message catalog name paired with its input source.]
[n:show?Show commands but do not execute.]
[o:omit?Omit \btranslate\b(1) methods matching the \bksh\b(1)
	\apattern\a.]:[pattern]
[r:remove?Remove all translated message files and work directories.]
[s:share?Generate and install \bmsggen\b(1) machine independent binary
	message catalogs.]
[t:translate?Translate using \btranslate\b(1).]
[v:verify?Verify that translated message files satisfy \bgencat\b(1) syntax.]

[ file ... ]

[+SEE ALSO?\bgencat\b(1), \bksh\b(1), \bmsggen\b(1), \btranslate\b(1)]
'
	;;
*)	ARGV0=""
	USAGE="Dcd:gno:rstv [ file ... ]"
	;;
esac

usage()
{
	OPTIND=0
	getopts $ARGV0 "$USAGE" OPT '-?'
	exit 2
}

messages()
{
	if	[[ $PACKAGEROOT && -d $PACKAGEROOT ]]
	then	MSGROOT=$PACKAGEROOT
	else	MSGROOT=$HOME
	fi
	set -- $MSGROOT/arch/*/src/cmd/INIT/INIT.msg
	[[ -f $1 ]] || { print -u2 $"$command: INIT.msg: not found"; exit 1; }
	MSGROOT=${1%/src/cmd/INIT/INIT.msg}
	grep -l '^1' $MSGROOT/src/@(cmd|lib)/*/*.msg
}

integer n
typeset all cache dialect=- exec force omit op show verbose
typeset dir=$INSTALLROOT gen=gencat

while	getopts $ARGV0 "$USAGE" OPT
do	case $OPT in
	D)	debug=-D ;;
	a)	all=-a ;;
	c)	cache=-c ;;
	d)	dialect=$OPTARG ;;
	f)	force=1 ;;
	g)	op=generate ;;
	l)	op=list ;;
	n)	exec=print show=-n ;;
	o)	omit="-o $OPTARG" ;;
	r)	op=remove ;;
	s)	gen=msggen dir=$dir/share ;;
	t)	op=translate ;;
	v)	op=verify ;;
	*)	usage ;;
	esac
done
shift $OPTIND-1

[[ $INSTALLROOT ]] || { print -u2 $"$command: INSTALLROOT not defined"; exit 1; }

case $op in

generate)
	dir=$dir/lib/locale
	[[ -d $dir ]] || { print -u2 $"$command: $dir: not found"; exit 1; }
	(( ! $# )) && set -- C $(ls *-*.msg 2>/dev/null | sed 's,.*-\(.*\)\.msg,\1,' | sort -u)
	owd=$PWD
	for locale
	do	case $locale in
		C)	set -- $(messages) ;;
		*)	set -- *-$locale.msg ;;
		esac
		if	[[ ! -f $1 ]]
		then	print -u2 "$command: $locale: no message files"
		else	nwd=$dir/$locale/LC_MESSAGES
			[[ -d $nwd ]] || $exec mkdir -p $nwd || exit
			[[ -d $nwd ]] && { cd $nwd || exit; }
			for file
			do	case $file in
				/*)	name=${file##*/}
					name=${name%*.msg}
					;;
				*)	name=${file%-$locale.msg}
					file=$owd/$file
					;;
				esac
				if	[[ $force || ! $name -nt $file ]]
				then	print -u2 $locale $name:
					$exec rm -f $name $name.*
					$exec $gen $name $file
				fi
			done
			cd $owd
		fi
	done
	;;

list)	messages | sed 's,^.*/\(.*\)\.msg$,\1 &,'
	;;

remove)	(( !$# )) && set -- *.msg translate.tmp
	$exec rm -rf "$@"
	;;

translate)
	(( !$# )) && set -- $(messages)
	translate -lmv $all $cache $debug $omit $show $dialect "$@"
	;;

verify)	(( ! $# )) && set -- *.msg
	for file
	do	n=0
		while	read -r num txt
		do	if	[[ $num == +([0-9]) ]]
			then	((n++))
				if	[[ $n != $num ]]
				then	if	(( n == $num-1 ))
					then	print -u2 "$file: [$n] missing"
					else	print -u2 "$file: [$n-$(($num-1))] missing"
					fi
					n=$num
				fi
			fi
		done < $file
	done
	;;

*)	usage
	;;

esac
