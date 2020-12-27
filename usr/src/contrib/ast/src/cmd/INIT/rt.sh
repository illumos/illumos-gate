########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1994-2011 AT&T Intellectual Property          #
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
: rt - nmake test output filter

command=rt
flags='--silent --keepgoing'
failed=0
heading=1
verbose=0

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	ARGV0="-a $command"
	USAGE=$'
[-?
@(#)$Id: rt (AT&T Research) 2010-07-27 $
]
'$USAGE_LICENSE$'
[+NAME?rt - run "nmake test" and filter output]
[+DESCRIPTION?\brt\b runs \vnmake test\v and filters the regression
	test output to contain only test summary lines. If no \atest\a
	operands are specified then \btest\b is assumed. If \b-\b is
	specified then the \afile\a operands, or the standard input
	if no \afile\a operands are specified, are filtered instead
	of the output from \bnmake\b.]
[f:failed?Only list failed test results.]
[h!:heading?Enable per-file heading when more than one \afile\a operand
	follows \b-\b.]
[v:verbose?Run with \vREGRESSFLAGS=-v\v.]

[ test ... | - [ file ... ] ]

[+SEE ALSO?\bnmake\b(1), \bregress\b(1)]
[+CAVEATS?\brt\b guesses the regression test output style. Garbled
	output indicates a bad guess.]
'
	;;
*)	ARGV0=""
	USAGE="fhv"
	;;
esac

function usage
{
	OPTIND=0
	getopts $ARGV0 "$USAGE" OPT '-?'
	exit 2
}

while	getopts $ARGV0 "$USAGE" OPT
do	case $OPT in
	f)	failed=1 ;;
	h)	heading=0 ;;
	v)	(( verbose=$OPTARG )) && flags="$flags REGRESSFLAGS=-v" ;;
	esac
done
shift `expr $OPTIND - 1`

ifs=${IFS:-$' \t\n'}
set -o noglob
component=
dots='............................................'
bad=' ***'
style=unknown
integer tests errors signals lineno=0 skip=0
typeset -l lower

function results # tests errors signals
{
	integer t=$1 e=$2 s=$3
	typeset label note
	if	[[ $style != unknown ]] && (( errors >= 0 ))
	then	style=unknown
		if	(( !failed || errors ))
		then	if	(( failed ))
			then	print -r -n -- "$unit"
			fi
			if	(( t >= 0 ))
			then	if	(( t == 1))
				then	label="test "
				else	label=tests
				fi
				printf $'%s%5d %s' "$prefix" "$t" "$label"
				prefix=
			else	prefix="$prefix..........."
			fi
			if	(( s ))
			then	label=signal
				(( e=s ))
			else	label=error
			fi
			if	(( e != 1))
			then	label=${label}s
			fi
			if	(( e == 1 ))
			then	note=" $bad"
			elif	(( e > 1 ))
			then	note=$bad
			fi
			printf $'%s%5d %s%s\n' "$prefix" "$e" "$label" "$note"
		fi
	fi
}

function unit
{
	typeset x
	if	[[ $component ]]
	then	x=${component##*/}
		if	[[ " $x " != *' '$unit' '* && " $unit " != *' '$x' '* ]]
		then	if	[[ $component == cmd/?*lib/* ]]
			then	unit="$unit $x"
			else	unit="$x $unit"
			fi
		fi
	fi
	unit="$unit ${dots:1:${#dots}-${#unit}}"
	if	[[ $1 ]]
	then	unit="$unit..........."
	fi
	if	(( ! failed ))
	then	print -r -n -- "$unit"
	fi
}

if	[[ $1 == - ]]
then	shift
	if	(( $# <= 1 ))
	then	heading=0
	fi
	if	(( heading ))
	then	for i
		do	print test heading $i
			cat -- "$i"
		done
	else	cat "$@"
	fi
else	if	[[ $1 == *=* ]]
	then	set test "$@"
	elif	(( ! $# ))
	then	set test
	fi
	nmake "$@" $flags 2>&1
fi |
while	read -r line
do	set '' $line
	shift
	case $line in
	TEST[' 	']*', '*' error'*)
		IFS=${IFS}","
		set '' $line
		IFS=$ifs
		set '' $*
		while	:
		do	case $2 in
			'')	break
				;;
			error|errors)
				errors=$1
				break
				;;
			test|tests)
				tests=$1
				;;
			esac
			shift
		done
		results $tests $errors
		continue
		;;
	TEST[' 	']*)
		results $tests $errors
		IFS=${IFS}","
		set '' $line
		IFS=$ifs
		set '' $*
		unit=${3##*/}
		case $4 in
		[a-zA-Z]*)	unit="$unit $4" ;;
		esac
		unit
		prefix=
		errors=0
		signals=0
		style=regress
		continue
		;;
	'pathname and options of item under test')
		read -r line || break
		results $tests $errors $signals
		set '' $line
		unit=${2##*/}
		unit
		tests=0
		errors=0
		signals=0
		style=script
		continue
		;;
	'test heading '*)
		if	(( heading ))
		then	if	(( heading > 1 ))
			then	print
			else	heading=2
			fi
			set '' $line
			shift 3
			print -r -- "==> $* <=="
		fi
		continue
		;;
	'test '*' begins at '????-??-??+??:??:??|'test '*' begins at '*' '*' '*' '*' '*)
		results $tests $errors $signals
		unit=${2##*/}
		unit=${unit%.sh}
		unit
		prefix=
		tests=-1
		errors=0
		signals=0
		style=shell
		continue
		;;
	'test '*' at '????-??-??+??:??:??' [ '*' ]'|'test '*' at '*' '*' '*' '*' '*)
		case $line in
		*' [ '*test*error*' ]')
			while	:
			do	case $1 in
				'[')	tests=$2
					errors=$4
					if	(( errors > 256 ))
					then	(( signals++ ))
					fi
					break
					;;
				esac
				shift
			done
			;;
		*' [ '*test*signal*' ]')
			while	:
			do	case $1 in
				'[')	tests=$2
					signals=$4
					if	(( signals ))
					then	(( errors++ ))
					fi
					break
					;;
				esac
				shift
			done
			;;
		*)	if	[[ $3 != passed ]]
			then	(( errors )) || (( errors++ ))
			fi
			;;
		esac
		results $tests $errors $signals
		continue
		;;
	'## ---'*(-)'--- ##')
		(( ++lineno > skip )) || continue
		read -r line || break
		lower=$line
		set '' $lower
		case $lower in
		'##'*'test suite:'*'##')
			results $tests $errors $signals
			set -- ${lower//*suite:}
			set -- ${*//[.#]/}
			unit=$*
			if	[[ $unit == *' tests' ]]
			then	unit=${unit/' tests'/}
			fi
			main=$unit
			prefix=
			tests=0
			errors=0
			signals=0
			category=
			style=autotest
			(( skip = lineno + 1 ))
			unit
			continue
			;;
		esac
		;;
	+(-))	case $style in
		regress)	continue ;;
		esac
		(( ++lineno > skip )) || continue
		read -r line || break
		set '' $line
		case $line in
		'Running tests for '*)
			results $tests $errors $signals
			shift 4
			unit=
			while	(( $# ))
			do	if	[[ $1 == on ]]
				then	break
				fi
				if	[[ $unit ]]
				then	unit="$unit "
				fi
				unit=$unit${1##*/}
				shift
			done
			main=$unit
			prefix=
			tests=-1
			errors=-1
			category=
			style=perl
			(( skip = lineno + 1 ))
			continue
			;;
		*' : '*)results $tests $errors $signals
			unit=${2##*/}
			unit=${unit%.sh}
			unit
			prefix=
			tests=0
			errors=0
			signals=0
			style=timing
			(( skip = lineno + 1 ))
			continue
			;;
		esac
		;;
	+([0-9])*([a-zA-Z0-9])' '*)
		case $style in
		script)	case $line in
			*FAILED*|*failed*)
				(( errors++ ))
				;;
			*)	(( tests++ ))
				;;
			esac
			;;
		esac
		;;
	make:*|'make ['*']:'*)
		case $line in
		*': warning:'*|*'making test'*|*'action'?(s)' failed'*|*': *** '*)
			;;
		*)	results $tests $errors $signals
			print -r -u2 -- "$line"
			;;
		esac
		continue
		;;
	+([/a-zA-Z_0-9]):)
		component=${line%:}
		;;
	'')	continue
		;;
	esac
	case $style in
	autotest)
		case $line in
		+([0-9]):*ok)
			(( tests++ ))
			;;
		+([0-9]):*FAILED*)
			(( tests++ ))
			(( errors++ ))
			if	(( $verbose ))
			then	if	[[ ! $prefix ]]
				then	prefix=$unit
					print
				fi
				print -r -- "	${line//*'FAILED '/}"
			fi
			;;
		esac
		continue
		;;
	perl)	case $line in
		*'........ '*)
			if	[[ $1 == */* ]]
			then	cat=${1%%/*}
				if	[[ $cat != $category ]]
				then	results $tests $errors $signals
					category=$cat
					unit="$main $category"
					unit
					prefix=
					tests=0
					errors=0
					signals=0
				fi
				(( tests++ ))
				case $line in
				*' ok')	;;
				*)	(( errors++ ))
					if	(( $verbose ))
					then	if	[[ ! $prefix ]]
						then	prefix=$unit
							print
						fi
						print -r -- "$line"
					fi
					;;
				esac
			else	results $tests $errors $signals
				case $line in
				*' ok')	errors=0 ;;
				*)	errors=1 ;;
				esac
				unit="$main $1"
				unit
				if	(( $verbose && errors ))
				then	prefix=$unit
					print
					shift 2
					print -r -- "$@"
				else	prefix=
				fi
				results $tests $errors $signals
				tests=-1
				errors=-1
				category=
			fi
			style=perl
			;;
		esac
		continue
		;;
	esac
	case $line in
	*FAILED*|*failed*)
		(( errors++ ))
		;;
	*)	case $style in
		regress)case $line in
			['<>']*);;
			*)	continue ;;
			esac
			;;
		script)	continue
			;;
		shell)	((errors++ ))
			;;
		timing)	(( tests++ ))
			continue
			;;
		unknown)continue
			;;
		esac
		;;
	esac
	if	(( $verbose ))
	then	if	[[ ! $prefix ]]
		then	prefix=$unit
			print
		fi
		print -r -- "$line"
	fi
done
results $tests $errors $signals
