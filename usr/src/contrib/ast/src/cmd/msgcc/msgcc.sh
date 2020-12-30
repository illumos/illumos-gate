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
: C language message catalog compiler

# NOTE: all variable names match __*__ to avoid clash with msgcpp def vars

__command__=msgcc
integer __similar__=30

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	ARGV0="-a $__command__"
	USAGE=$'
[-?
@(#)$Id: msgcc (AT&T Labs Research) 2010-10-20 $
]
'$USAGE_LICENSE$'
[+NAME?msgcc - C language message catalog compiler]
[+DESCRIPTION?\bmsgcc\b is a C language message catalog compiler. It accepts
	\bcc\b(1) style options and arguments. A \bmsgcpp\b(1) \b.mso\b file
	is generated for each input \b.c\b file. If the \b-c\b option is not
	specified then a \bgencat\b(1) format \b.msg\b file is generated from
	the input \b.mso\b and \b.msg\b files. If \b-c\b is not specified then
	a \b.msg\b suffix is appended to the \b-o\b \afile\a if it doesn\'t
	already have a suffix. The default output is \ba.out.msg\b if \b-c\b
	and \b-o\b are not specified.]
[+?If \b-M-new\b is not specified then messages are merged with those in the
	pre-existing \b-o\b file.]
[M?Set a \bmsgcc\b specific \aoption\a. \aoption\a may be:]:[-option]{
	[+mkmsgs?The \b-o\b file is assumed to be in \bmkmsgs\b(1) format.]
	[+new?Create a new \b-o\b file.]
	[+preserve?Messages in the \b-o\b file that are not in new
		\b.msg\b file arguments are preserved. The default is to
		either reuse the message numbers with new message text that
		is similar to the old or to delete the message text, leaving
		an unused message number.]
	[+set=\anumber\a?Set the message set number to \anumber\a. The default
		is \b1\b.]
	[+similar=\anumber\a?The message text similarity measure threshold.
		The similarity measure between \aold\a and \anew\a message
		text is 100*(2*gzip(\aold\a+\anew\a)/(gzip(\aold\a)+gzip(\anew\a))-1),
		where gzip(\ax\a) is the size of text \ax\a when compressed by
		\bgzip\b(1). The default threshold is '$__similar__$'. A
		threshold of \b0\b turns off message replacement, but unused
		old messages are still deleted. Use \b-M-preserve\b to preserve
		all old messages.]
	[+verbose?Trace similar message replacements on the standard error.]
}

file ...

[+SEE ALSO?\bcc\b(1), \bcpp\b(1), \bgencat\b(1), \bmsggen\b(1),
	\bmsgcpp\b(1), \bmsgcvt\b(1)]
'
	;;
*)	ARGV0=""
	USAGE="M:[-option] [ cc-options ] file ..."
	;;
esac

usage()
{
	OPTIND=0
	getopts $ARGV0 "$USAGE" OPT '-?'
	exit 2
}

keys()
{
	$1 --??keys -- 2>&1 | grep '^".*"$'
}

typeset -A __index__
typeset __keep__ __text__ __drop__ __oz__ __nz__ __z__ __hit__ __hit_i__
typeset __compile__ __debug__ __mkmsgs__ __preprocess__
typeset __merge__=1 __preserve__ __verbose__
integer __i__=0 __args__=0 __code__=0 __files__=0 __max__=0 __num__=0 __skip__=0
integer __set__=1 __sources__=0 __cmds__=0 __ndrop__=0 __new__=0 __old__=0
__out__=a.out.msg
__OUT__=

case " $* " in
*" --"*|*" -?"*)
	while	getopts $ARGV0 "$USAGE" OPT
	do	case $OPT in
		*)	break ;;
		esac
	done
	;;
esac
while	:
do	case $# in
	0)	break ;;
	esac
	__arg__=$1
	case $__arg__ in
	-c)	__compile__=1
		;;
	-[DIU]*)__argv__[__args__]=$__arg__
		(( __args__++ ))
		;;
	-E)	__preprocess__=1
		;;
	-M-debug)
		__debug__=1
		;;
	-M-mkmsgs)
		__mkmsgs__=1
		;;
	-M-new)	__merge__=
		;;
	-M-perserve)
		__preserve__=1
		;;
	-M-set=*)
		__set__=$(msggen -s ${__arg__#*=}.1)
		;;
	-M-similar=*)
		__similar__=${__arg__#*=}
		;;
	-M-verbose)
		__verbose__=1
		;;
	-o)	case $# in
		1)	print -u2 $"$__command__: output argument expected"
			exit 1
			;;
		esac
		shift
		__out__=${1%.*}.msg
		__OUT__=$1
		;;
	[-+]*|*.[aAlLsS]*)
		;;
	*.[cCiI]*|*.[oO]*)
		case $__arg__ in
		*.[oO]*);;
		*)	__srcv__[__files__]=$__arg__
			(( __sources__++ ))
			;;
		esac
		__arg__=${__arg__##*/}
		__arg__=${__arg__%.*}.mso
		__objv__[__files__]=$__arg__
		(( __files__++ ))
		;;
	*.ms[go])
		__objv__[__files__]=$__arg__
		(( __files__++ ))
		;;
	*)	__cmdv__[__cmds__]=$__arg__
		(( __cmds__++ ))
		;;
	esac
	shift
done
__arg__=${__out__##*/}
__arg__=${__arg__%.msg}
if	[[ -x $__arg__ ]]
then	__cmdv__[__cmds__]=$__arg__
	(( __cmds__++ ))
fi

# generate the .mso files

if	[[ $__OUT__ && $__compile__ ]]
then	__objv__[0]=$__OUT__
fi

if	(( __sources__ ))
then	for (( __i__=0; __i__<=__files__; __i__++ ))
	do	if	[[ ${__srcv__[__i__]} ]]
		then	if	(( __sources__ > 1 ))
			then	print "${__srcv__[__i__]}:"
			fi
			if	[[ $__preprocess__ ]]
			then	msgcpp "${__argv__[@]}" "${__srcv__[__i__]}"
			else	msgcpp "${__argv__[@]}" "${__srcv__[__i__]}" > "${__objv__[__i__]}"
			fi
		fi
	done
fi

# combine the .mso and .msg files

if	[[ ! $__compile__ && ! $__preprocess__ ]]
then	if	[[ $__merge__ && -r $__out__ ]]
	then	__tmp__=$__out__.tmp
		trap '__code__=$?; rm -f ${__tmp__}*; exit $__code__' 0 1 2
		while	read -r __line__
		do	if	(( $__skip__ ))
			then	if	[[ $__line__ == '%}'* ]]
				then	__skip__=0
				fi
				continue
			fi
			if	[[ $__mkmsgs__ && $__line__ == '%{'* ]]
			then	__skip__=1
				continue
			fi
			if	[[ $__mkmsgs__ ]]
			then	if	[[ $__line__ == '%#'*';;'* ]]
				then	__line__=${__line__#'%#'}
					__num__=${__line__%';;'*}
					read -r __line__
				elif	[[ $__line__ == %* ]]
				then	continue
				else	print -u2 $"$__command__: unrecognized line=$__line__"
					__code__=1
				fi
			else	case $__line__ in
				+([0-9])' '*)
					__num__=${__line__%%' '*}
					__line__=${__line__#*'"'}
					__line__=${__line__%'"'}
					;;
				*)	continue
					;;
				esac
			fi
			__index__["$__line__"]=$__num__
			__text__[$__num__]=$__line__
			if	(( __max__ < __num__ ))
			then	(( __max__=__num__ ))
			fi
		done < $__out__
		(( __new__=__max__+1 ))
	else	__tmp__=$__out__
		(( __new__=1 ))
	fi
	if	(( __code__ ))
	then	exit $__code__
	fi
	exec 1>$__tmp__ 9>&1
	print -r -- '$'" ${__out__%.msg} message catalog"
	print -r -- '$translation'" $__command__ $(date +%Y-%m-%d)"
	print -r -- '$set'" $__set__"
	print -r -- '$quote "'
	sort -u "${__objv__[@]}" | {
		__raw__=
		while	read -r __line__
		do	__op__=${__line__%% *}
			__line__=${__line__#* }
			case $__op__ in
			cmd)	__a1__=${__line__%% *}
				case $__a1__ in
				dot_cmd)	__a1__=. ;;
				esac
				keys $__a1__
				;;
			def)	__a1__=${__line__%% *}
				__a2__=${__line__#* }
				eval $__a1__='$'__a2__
				;;
			str)	print -r -- "$__line__"
				;;
			raw)	__raw__=$__raw__$'\n'$__line__
				;;
			var)	__a1__=${__line__%% *}
				__a2__=${__line__#* }
				case $__a1__ in
				[[:digit:]]*)
					eval __v__='$'$__a2__
					__v__='"'${__v__:__a1__+1}
					;;
				*)	eval __v__='$'$__a1__
					;;
				esac
				if	[[ $__v__ == '"'*'"' ]]
				then	print -r -- "$__v__"
				fi
				;;
			[[:digit:]]*)
				[[ $__preserve__ ]] && print -r -- "$__line__"
				;;
			'$')	print -r -u9 $__op__ include $__line__
				;;
			esac
		done
		for (( __i__=0; __i__ < __cmds__; __i__++ ))
		do	keys ${__cmdv__[__i__]}
		done
		[[ $__raw__ ]] && print -r "${__raw__#?}" | sed -e 's/^"//' -e 's/"$//' -e 's/\\/&&/g' -e 's/"/\\"/g' -e 's/.*/$RAW$"&"/'
	} | {
		__num__=1
		while	read -r __line__
		do	case $__line__ in
			'$RAW$'*)
				;;
			'$'[\ \	]*)
				print -r -- "$__line__"
				continue
				;;
			'$'*|*"@(#)"*|*"<"*([[:word:] .-])"@"*([[:word:] .-])">"*([ 	])'"'|"http://"*)
				continue
				;;
			*[[:alpha:]][[:alpha:]]*)
				;;
			*)	continue
				;;
			esac
			__line__=${__line__#*'"'}
			__line__=${__line__%'"'}
			if	[[ $__line__ ]]
			then	if	[[ ${__index__["$__line__"]} ]]
				then	if [[ ! $__preserve__ ]]
					then	__num__=${__index__["$__line__"]}
						__keep__[$__num__]=1
					fi
				else	while	 [[ ${__text__[$__num__]} ]]
					do	(( __num__++ ))
					done
					if	(( __max__ < __num__ ))
					then	(( __max__=__num__ ))
					fi
					if	[[ ! $__preserve__ ]]
					then	 __keep__[$__num__]=1
					fi
					__text__[$__num__]=$__line__
					__index__["$__line__"]=$__num__
					(( __num__++ ))
				fi
			fi
		done
		if	(( __max__ < __num__ ))
		then	(( __max__=__num__ ))
		fi
		if [[ $__debug__ ]]
		then	for (( __num__=1; __num__<=__max__; __num__++ ))
			do	if	[[ ${__text__[$__num__]} ]]
				then	if	(( __num__ > __new__ ))
					then	if	[[ ! ${__keep__[$__num__]} ]]
						then	print -r -u2 -- $__num__ HUH '"'"${__text__[$__num__]}"'"'
						else	print -r -u2 -- $__num__ NEW '"'"${__text__[$__num__]}"'"'
						fi
					elif	[[ ${__keep__[$__num__]} ]]
					then	print -r -u2 -- $__num__ OLD '"'"${__text__[$__num__]}"'"'
					else	print -r -u2 -- $__num__ XXX '"'"${__text__[$__num__]}"'"'
					fi
				fi
			done
			exit 0
		fi
		# check for replacements
		if	[[ ! $__preserve__ ]]
		then	for (( __num__=1; __num__<__new__; __num__++ ))
			do	if	[[ ${__text__[$__num__]} && ! ${__keep__[$__num__]} ]]
				then	(( __ndrop__++ ))
					__drop__[__ndrop__]=$__num__
				fi
			done
			[[ $__verbose__ ]] && print -u2 $__command__: old:1-$((__new__-1)) new:$__new__-$__max__ drop $__ndrop__ add $((__max__-__new__+1))
			if	(( __ndrop__ ))
			then	for (( __i__=1; __i__<=__ndrop__; __i__++ ))
				do	(( __old__=${__drop__[$__i__]} ))
					__oz__[__i__]=$(print -r -- "\"${__text__[$__old__]}\"" | gzip | wc -c)
				done
				for (( __num__=__new__; __num__<=__max__; __num__++ ))
				do	[[ ${__text__[$__num__]} ]] || continue
					__nz__=$(print -r -- "\"${__text__[$__num__]}\"" | gzip | wc -c)
					__hit__=0
					(( __bz__=__similar__ ))
					for (( __i__=1; __i__<=__ndrop__; __i__++ ))
					do	if	(( __old__=${__drop__[$__i__]} ))
						then	__z__=$(print -r -- "\"${__text__[$__old__]}\"""\"${__text__[$__num__]}\"" | gzip | wc -c)
							(( __z__ = (__z__ * 200 / (${__oz__[__i__]} + $__nz__)) - 100 ))
							if	(( __z__ < __bz__ ))
							then	(( __bz__=__z__ ))
								(( __hit__=__old__ ))
								(( __hit_i__=__i__ ))
							fi
						fi
					done
					if	(( __hit__ ))
					then	[[ $__verbose__ ]] && print -u2 $__command__: $__hit__ $__num__ $__bz__
						__text__[$__hit__]=${__text__[$__num__]}
						__keep__[$__hit__]=1
						__drop__[$__hit_i__]=0
						__text__[$__num__]=
						__keep__[$__num__]=
					fi
				done
			fi
		fi
		# final output
		for (( __num__=1; __num__<=__max__; __num__++ ))
		do	if	[[ ${__text__[$__num__]} && ( $__preserve__ || ${__keep__[$__num__]} ) ]]
			then	print -r -- $__num__ "\"${__text__[$__num__]}\""
			fi
		done
	}
	if [[ $__tmp__ != $__out__ ]]
	then	grep -v '^\$' $__tmp__ > ${__tmp__}n
		[[ -f $__out__ ]] && grep -v '^\$' $__out__ > ${__tmp__}o
		cmp -s ${__tmp__}n ${__tmp__}o || {
			[[ -f $__out__ ]] && mv $__out__ $__out__.old
			mv $__tmp__ $__out__
		}
	fi
fi
exit $__code__
