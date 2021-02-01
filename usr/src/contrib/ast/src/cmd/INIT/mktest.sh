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
: mktest - generate regress or shell regression test scripts

command=mktest
stdin=8
stdout=9
PREFIX=test
STYLE=regress
WIDTH=80

eval "exec $stdout>&1"

case $(getopts '[-][123:xyz]' opt --xyz 2>/dev/null; echo 0$opt) in
0123)	ARGV0="-a $command"
	USAGE=$'
[-?
@(#)$Id: mktest (AT&T Labs Research) 2010-08-11 $
]
'$USAGE_LICENSE$'
[+NAME?mktest - generate a regression test scripts]
[+DESCRIPTION?\bmktest\b generates regression test scripts from test
    template commands in the \aunit\a.\brt\b file. The generated test
    script writes temporary output to '$PREFIX$'\aunit\a.tmp and compares
    it to the expected output in '$PREFIX$'\aunit\a.out. Run the test
    script with the \b--accept\b option to (re)generate the
    '$PREFIX$'\aunit\a.out.]
[s:style?The script style:]:[style:='$STYLE$']
    {
        [+regress?\bregress\b(1) command input.]
        [+shell?Standalone test shell script.]
    }
[w:width?Set the output format width to approximately
    \awidth\a.]:[width:='$WIDTH$']

unit.rt [ unit [ arg ... ] ]

[+INPUT FILES?The regression test command file \aunit\a\b.rt\b is a
    \bksh\b(1) script that makes calls to the following functions:]
    {
        [+DATA \afile\a [ - | [ options ]] data]]?Create input data
            \afile\a that is empty (-) or contains \adata\a subject to
            \bprint\b(1) \aoptions\a or that is a copy of the DATA command
            standard input. Set \afile\a to \b-\b to name the standard
            input.]
        [+DIAGNOSTICS?Diagnostic messages of unspecified format are
	    expected.]
        [+DO \acommand\a [ \aarg\a ... ]]?Execute \acommand\a if the
	    current test is active.]
        [+EXEC [ \aarg\a ... ]]?Run the command under test with
            optional arguments. If the standard input is not specified then
            the standard input of the previous EXEC is used. The standard
            input of the first EXEC in a TEST group is an empty regular
            file.]
        [+EXPORT \aname\a=\avalue\a ...?Export list for subsequent
            commands in the TEST group or for all TEST groups if before
	    the first TEST group.]
        [+IGNORESPACE [ 0 | 1 ]
            ?Ignore space differences when comparing expected output.]
        [+KEEP \apattern\a ...?File match patterns of files to retain
            between TEST groups.]
        [+NOTE \acomment\a?\acomment\a is added to the current test
            script.]
        [+PROG \acommand\a [ \aarg\a ... ]]?Run \acommand\a with
            optional arguments.]
        [+TEST [ \anumber\a ]] [ \adescription\a ... ]]?Define a new
            test group with optional \anumber\a and \adescripion\a.]
        [+TWD [ \adir\a ... ]]?Set the temporary test dir to \adir\a.
            The default is \aunit\a\b.tmp\b, where \aunit\a is the test
            input file sans directory and suffix. If \adir\a matches \b/*\b
            then it is the directory name; if \adir\a is non-null then the
            prefix \b${TMPDIR:-/tmp}\b is added; otherwise if \adir\a is
            omitted then
            \b${TMPDIR:-/tmp}/tst-\b\aunit\a-$$-$RANDOM.\b\aunit\a is
            used.]
        [+UMASK [ \amask\a ]]?Run subsequent tests with \bumask\b(1)
            \amask\a. If \amask\a is omitted then the original \bumask\b is
            used.]
        [+UNIT \acommand\a [ \aarg\a ... ]]?Define the command and
            optional default arguments to be tested. \bUNIT\b explicitly
            overrides the default command name derived from the test script
            file name.]
        [+WIDTH \awidth\a?Set the output format width to approximately
            \awidth\a.]
    }
[+SEE ALSO?\bregress\b(1), \bksh\b(1)]
'
	;;
*)	ARGV0=""
	USAGE='s: unit.rt [ arg ... ]'
	;;
esac

typeset ARG SCRIPT UNIT TEMP=${TMPDIR:-/tmp}/$command.$$.tmp WORK
typeset IO INPUT INPUT_N OUTPUT OUTPUT_N ERROR ERROR_N KEEP
typeset -C STATE
typeset -A DATA STATE.RESET REMOVE FORMAT
integer KEEP_UNIT=0 SCRIPT_UNIT=0 TEST=0 CODE=0 EXIT=0 ACCEPT=0 DIAGNOSTICS=0 code

while	getopts $ARGV0 "$USAGE" OPT
do	case $OPT in
	s)	case $OPTARG in
		regress|shell)
			STYLE=$OPTARG
			;;
		*)	print -u2 -r -- $command: --style=$OPTARG: regress or shell expected
			exit 1
			;;
		esac
		;;
	w)	WIDTH=$OPTARG
		;;
	*)	OPTIND=0
		getopts $ARGV0 "$USAGE" OPT '-?'
		exit 2
		;;
	esac
done
shift $OPTIND-1

typeset SINGLE= quote='%${SINGLE}..${WIDTH}q'

if	[[ $1 == - ]]
then	shift
fi
if	(( ! $# ))
then
	print -u2 -r -- $command: test command script path expected
	exit 1
fi
SCRIPT=$1
shift
if	[[ ! -r $SCRIPT ]]
then	print -u2 -r -- $command: $SCRIPT: cannot read
	exit 1
fi
(ulimit -c 0) >/dev/null 2>&1 && ulimit -c 0
if	(( $# ))
then	set -A UNIT -- "$@"
	KEEP_UNIT=1
else	ARG=${SCRIPT##*/}
	set -A UNIT -- "${ARG%.*}"
fi
WORK=${UNIT[0]}.tmp
rm -rf $WORK
mkdir $WORK || exit
export PATH=$PWD:$PATH

function LINE
{
	if	[[ $STYLE == regress ]]
	then	print -u$stdout
	fi
}

function NOTE
{
	case $STYLE in
	regress)LINE
		print -u$stdout -r -- '#' "$@"
		;;
	shell)	print -u$stdout -r -f ": $QUOTE"$'\n' -- "$*"
		;;
	esac
}

function UNIT
{
	(( KEEP_UNIT )) || set -A UNIT -- "$@"
	case $STYLE in
	regress)LINE
		print -u$stdout -r -f $'UNIT'
		for ARG in "$@"
		do	print -u$stdout -r -f " $QUOTE" -- "$ARG"
		done
		print -u$stdout
		;;
	shell)	print -u$stdout -r -f $'set x'
		for ARG in "$@"
		do	print -u$stdout -r -f " $QUOTE" -- "$ARG"
		done
		print -u$stdout
		print -u$stdout shift
		;;
	esac
}

function TEST
{
	typeset i
	typeset -A REM
	if	(( ${#STATE.RESET[@]} ))
	then	unset ${!STATE.RESET[@]}
		case $STYLE in
		shell)	print -u$stdout -r -- unset ${!STATE.RESET[@]} ;;
		esac
		unset STATE.RESET
		typeset -A STATE.RESET
	fi
	if	(( ${#REMOVE[@]} ))
	then	rm -f -- "${!REMOVE[@]}"
		case $STYLE in
		shell)	print -u$stdout -r -f $'rm -f'
			for i in ${!REMOVE[@]}
			do	print -u$stdout -r -f " $QUOTE" "$i"
			done
			print -u$stdout
			;;
		esac
		for i in ${!REMOVE[@]}
		do	unset REMOVE[$i]
		done
	fi
	rm -rf $WORK/*
	if	[[ $1 == +([0-9]) ]]
	then	TEST=${1##0}
		shift
	else	((TEST++))
	fi
	LINE
	case $STYLE in
	regress)print -u$stdout -r -f "TEST %02d $QUOTE"$'\n' -- $TEST "$*"
		;;
	shell)	print -u$stdout -r -f ": TEST %02d $QUOTE"$'\n' -- $TEST "$*"
		;;
	esac
	: > $TEMP.INPUT > $TEMP.in
	INPUT=
	INPUT_N=
	OUTPUT=
	OUTPUT_N=
	ERROR=
	ERROR_N=
	UMASK=$UMASK_ORIG
	UMASK_DONE=$UMASK
	CODE=0
}

function TWD
{
	case $STYLE in
	regress)LINE
		print -u$stdout -r -f $'TWD'
		for ARG in "$@"
		do	print -u$stdout -r -f " $QUOTE" -- "$ARG"
		done
		print -u$stdout
		;;
	esac
}

function RUN
{
	typeset i n p op unit sep output=1 error=1 exitcode=1
	op=$1
	shift
	while	:
	do	case $1 in
		++NOOUTPUT)	output= ;;
		++NOERROR)	error= ;;
		++NOEXIT)	exitcode= ;;
		++*)		print -u2 -r -- $command: $0: $1: unknown option; exit 1 ;;
		*)		break ;;
		esac
		shift
	done
	if	[[ $op == PROG ]]
	then	unit=$1
		shift
	elif	(( ! ${#UNIT[@]} ))
	then	print -u2 -r -- $command: $SCRIPT: UNIT statement or operand expected
		exit 1
	fi
	LINE
	case $STYLE in
	regress)if	[[ $op == PROG ]]
		then	print -u$stdout -r -f $'\t'"$op"$'\t'"$unit"
			sep=$' '
		else	print -u$stdout -r -f $'\t'"$op"
			sep=$'\t'
		fi
		for ARG in "$@"
		do	LC_CTYPE=C print -u$stdout -r -f "$sep$QUOTE" -- "$ARG"
			sep=$' '
		done
		print -u$stdout
		[[ ${DATA[-]} || /dev/fd/0 -ef /dev/fd/$stdin ]] || cat > $TEMP.in
		IO=$(cat $TEMP.in; print :)
		if	[[ $IO == ?*$'\n:' ]]
		then	IO=${IO%??}
			n=
		else	IO=${IO%?}
			n=-n
		fi
		{
			[[ $UMASK != $UMASK_ORIG ]] && umask $UMASK
			cd $WORK
			if	[[ $op == PROG ]]
			then	"$unit" "$@"
				code=$?
			else	"${UNIT[@]}" "$@"
				code=$?
			fi
			cd ..
			[[ $UMASK != $UMASK_ORIG ]] && umask $UMASK_ORIG
		} < $TEMP.in > $TEMP.out 2> $TEMP.err
		if	[[ $IO != "$INPUT" || $n != "$INPUT_N" ]]
		then	INPUT=$IO
			INPUT_N=$n
			if	[[ ${FORMAT[-]} ]]
			then	print -u$stdout -n -r -- $'\t\tINPUT'
				print -u$stdout -r -f " $QUOTE" -- "${FORMAT[-]}"
				print -u$stdout -r -f " $QUOTE" -- -
				unset FORMAT[-]
			else	print -u$stdout -n -r -- $'\t\tINPUT' $n -
				[[ $IO ]] && LC_CTYPE=C print -u$stdout -r -f " $QUOTE" -- "$IO"
			fi
			print -u$stdout
			unset DATA[-]
		fi
		for i in ${!DATA[@]}
		do	if	[[ ${FORMAT[$i]} ]]
			then	print -u$stdout -n -r -- $'\t\tINPUT'
				print -u$stdout -r -f " $QUOTE" -- "${FORMAT[$i]}"
				print -u$stdout -r -f " $QUOTE" -- "$i"
				unset FORMAT[$i]
			else	case $i in
				-)	p=$TEMP.in ;;
				*)	p=$WORK/$i ;;
				esac
				IO=$(cat $p; print :)
				if	[[ $IO == ?*$'\n:' ]]
				then	IO=${IO%??}
					n=
				else	IO=${IO%?}
					n=-n
				fi
				print -u$stdout -n -r -- $'\t\tINPUT' $n
				print -u$stdout -r -f " $QUOTE" -- "$i"
				[[ $IO ]] && LC_CTYPE=C print -u$stdout -r -f " $QUOTE" -- "$IO"
			fi
			print -u$stdout
			unset DATA[$i]
		done
		IO=$(cat $TEMP.out; print :)
		if	[[ $IO == ?*$'\n:' ]]
		then	IO=${IO%??}
			n=
		else	IO=${IO%?}
			n=-n
		fi
		if	[[ $IO != "$OUTPUT" || $n != "$OUTPUT_N" ]]
		then	OUTPUT=$IO
			OUTPUT_N=$n
			if	[[ $output ]]
			then	if	[[ ! -s $TEMP.out ]]
				then	print -u$stdout -n -r -- $'\t\tOUTPUT' -
				elif	cmp -s $TEMP.in $TEMP.out
				then	OUTPUT=not-$OUTPUT
					print -u$stdout -n -r -- $'\t\tSAME OUTPUT INPUT'
				else	print -u$stdout -n -r -- $'\t\tOUTPUT' $n -
					[[ $IO ]] && LC_CTYPE=C print -u$stdout -r -f " $QUOTE" -- "$IO"
				fi
				print -u$stdout
			fi
		fi
		IO=$(cat $TEMP.err; print :)
		IO=${IO//$command\[*([0-9])\]:\ .\[*([0-9])\]:\ @(EXEC|PROG)\[*([0-9])\]:\ /}
		if	[[ $IO == ?*$'\n:' ]]
		then	IO=${IO%??}
			n=
		else	IO=${IO%?}
			n=-n
		fi
		if	[[ $IO != "$ERROR" || $n != "$ERROR_N" ]]
		then	ERROR=$IO
			ERROR_N=$n
			if	[[ $error ]]
			then	print -u$stdout -n -r -- $'\t\tERROR' $n -
				[[ $IO ]] && LC_CTYPE=C print -u$stdout -r -f " $QUOTE" -- "$IO"
				print -u$stdout
			fi
		fi
		case $output:$error in
		:)	OUTPUT=
			OUTPUT_N=
			ERROR=
			ERROR_N=
			print -u$stdout -r -- $'\t\tIGNORE OUTPUT ERROR'
			;;
		:1)	OUTPUT=
			OUTPUT_N=
			print -u$stdout -r -- $'\t\tIGNORE OUTPUT'
			;;
		1:)	ERROR=
			ERROR_N=
			print -u$stdout -r -- $'\t\tIGNORE ERROR'
			;;
		esac
		if	[[ $UMASK_DONE != $UMASK ]]
		then	UMASK_DONE=$UMASK
			print -u$stdout -r -f $'\t\tUMASK %s\n' $UMASK
		fi
		if	(( code != CODE ))
		then	(( CODE=code ))
			if	[[ $exitcode ]]
			then	print -u$stdout -r -f $'\t\tEXIT %d\n' $CODE
			fi
		fi
		;;
	shell)	[[ $UMASK != $UMASK_ORIG ]] && print -u$stdout -r -f "{ umask $UMASK; "
		if	[[ $op == PROG ]]
		then	print -u$stdout -r -f $'"'"$unit"$'"'
		else	print -u$stdout -r -f $'"$@"'
		fi
		for ARG in "$@"
		do	print -u$stdout -r -f " $QUOTE" -- "$ARG"
		done
		[[ $UMASK != $UMASK_ORIG ]] && print -u$stdout -r -f "umask $UMASK_ORIG; } "
		if	[[ ! $output ]]
		then	print -u$stdout -r -f " >/dev/null"
		fi
		if	[[ ! $error ]]
		then	if	[[ ! $output ]]
			then	print -u$stdout -r -f " 2>&1"
			else	print -u$stdout -r -f " 2>/dev/null"
			fi
		fi
		IO=$(cat)
		if	[[ $IO ]]
		then	print -u$stdout -r -- "<<'!TEST-INPUT!'"
			print -u$stdout -r -- "$IO"
			print -u$stdout -r -- !TEST-INPUT!
		else	print -u$stdout
		fi
		if	[[ $exitcode ]]
		then	print -u$stdout -r -- $'CODE=$?\ncase $CODE in\n0) ;;\n*) echo exit status $CODE ;;\nesac'
		fi
		;;
	esac
}

function DO
{
	LINE
	print -r $'\t'DO "$@"
}

function EXEC
{
	RUN EXEC "$@"
}

function DATA
{
	typeset f p o
	f=$1
	shift
	case $f in
	-)	p=$TEMP.in ;;
	*)	p=$WORK/$f ;;
	esac
	case $1 in
	'')	cat ;;
	-)	;;
	*)	print -r "$@" ;;
	esac > $p
	DATA[$f]=1
	if	(( $# == 1 )) && [[ $1 == -?* ]]
	then	FORMAT[$f]=$1
	else	FORMAT[$f]=
	fi
	if	[[ $f != $KEEP ]]
	then	REMOVE[$f]=1
	fi
	if	[[ $STYLE == shell ]]
	then	{
		print -r -f "cat > $QUOTE <<'!TEST-INPUT!'"$'\n' -- "$f"
		cat "$p"
		print -r -- !TEST-INPUT!
		} >&$stdout
	fi
}

function KEEP
{
	typeset p
	for p
	do	if	[[ $KEEP ]]
		then	KEEP=$KEEP'|'
		fi
		KEEP=$KEEP$p
	done
}

function DIAGNOSTICS
{
	LINE
	case $STYLE in
	regress)	print -u$stdout -r $'DIAGNOSTICS' ;;
	shell)		DIAGNOSTICS=1 ;;
	esac
}

function EXPORT
{
	typeset x n v
	LINE
	case $STYLE in
	regress)	print -u$stdout -r -f $'EXPORT' ;;
	shell)		print -u$stdout -r -f $'export' ;;
	esac
	for x
	do	n=${x%%=*}
		v=${x#*=}
		export "$x"
		print -u$stdout -r -f " %s=$QUOTE" "$n" "$v"
		(( TEST )) && STATE.RESET["$n"]=1
	done
	print -u$stdout
}

function PROG
{
	RUN PROG "$@"
}

function WIDTH
{
	WIDTH=${1:-80}
	eval QUOTE='"'$quote'"'
}

function IGNORESPACE
{
	IGNORESPACE=-b
	LINE
	print -u$stdout -r IGNORESPACE
}

function UMASK # [ mask ]
{
	[[ $UMASK_ORIG ]] || UMASK_ORIG=$(umask)
	UMASK=$1
	[[ $UMASK ]] || UMASK=$UMASK_ORIG
}

trap 'CODE=$?; rm -rf $TEMP.* $WORK; exit $CODE' 0 1 2 3 15

typeset IGNORESPACE UMASK UMASK_ORIG UMASK_DONE
UMASK_ORIG=$(umask)
IFS=$IFS$'\n'

print -u$stdout -r "# : : generated from $SCRIPT by $command : : #"
case $STYLE in
shell)	cat <<!
ACCEPT=0
while	:
do	case \$1 in
	-a|--accept)
		ACCEPT=1
		;;
	--help|--man)
		cat 1>&2 <<!!
Usage: \\\$SHELL $PREFIX${UNIT[0]}.sh [ --accept ] [ unit ... ]

${UNIT[0]} regression test script.  Run this script to generate new
results in $PREFIX${UNIT[0]}.tmp and compare with expected results in
$PREFIX${UNIT[0]}.out.  The --accept option generates $PREFIX${UNIT[0]}.tmp
and moves it to $PREFIX${UNIT[0]}.out.
!!
		exit 2
		;;
	-*)	echo \$0: \$1: invalid option >&2
		exit 1
		;;
	*)	break
		;;
	esac
	shift
done
export COLUMNS=80
{
!
	;;
esac

export COLUMNS=80

case $STYLE in
shell)	SINGLE='#'
	eval QUOTE='"'$quote'"'
	. $SCRIPT < /dev/null | sed -e $'s,\\\\n,\n,g' -e $'s,\\\\t,\t,g' -e $'s,\\$\',\',g'
	;;
*)	eval QUOTE='"'$quote'"'
	: > $TEMP.INPUT > $TEMP.in
	eval "exec $stdin<$TEMP.INPUT"
	. $SCRIPT <&$stdin
	;;
esac

case $STYLE in
shell)	cat <<!
} > $PREFIX${UNIT[0]}.tmp 2>&1 < /dev/null
case \$ACCEPT in
0)	if	grep '$' $PREFIX${UNIT[0]}.tmp >/dev/null
	then	mv $PREFIX${UNIT[0]}.tmp $PREFIX${UNIT[0]}.junk
		sed 's/$//' < $PREFIX${UNIT[0]}.junk > $PREFIX${UNIT[0]}.tmp
		rm -f $PREFIX${UNIT[0]}.junk
	fi
	if	cmp -s $PREFIX${UNIT[0]}.tmp $PREFIX${UNIT[0]}.out
	then	echo ${UNIT[0]} tests PASSED
		rm -f $PREFIX${UNIT[0]}.tmp
	else	echo ${UNIT[0]} tests FAILED
		diff $IGNORESPACE $PREFIX${UNIT[0]}.tmp $PREFIX${UNIT[0]}.out
	fi
	;;

*)	mv $PREFIX${UNIT[0]}.tmp $PREFIX${UNIT[0]}.out
	;;
esac
!
	;;
esac
