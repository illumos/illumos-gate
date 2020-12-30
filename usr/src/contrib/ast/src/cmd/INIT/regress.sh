########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1994-2012 AT&T Intellectual Property          #
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
: regress - run regression tests in command.tst

command=regress
case $(getopts '[-][123:xyz]' opt --xyz 2>/dev/null; echo 0$opt) in
0123)	USAGE=$'
[-?
@(#)$Id: regress (AT&T Research) 2012-02-02 $
]
'$USAGE_LICENSE$'
[+NAME?regress - run regression tests]
[+DESCRIPTION?\bregress\b runs the tests in \aunit\a, or
    \aunit\a\b.tst\b if \aunit\a does not exist. If \acommand\a is omitted
    then it is assumed to be the base name of \aunit\a. All testing is done
    in the temporary directory \aunit\a\b.tmp\b.]
[+?Default test output lists the \anumber\a and \adescription\a for
    each active \bTEST\b group and the \anumber\a:\aline\a for each
    individual \bEXEC\b test. Each test that fails results in a diagnostic
    that contains the word \bFAILED\b; no other diagnostics contain this
    word.]
[b:ignore-space?Ignore space differences when comparing expected
    output.]
[i:pipe-input?Repeat each test with the standard input redirected through a
    pipe.]
[k:keep?Enable \bcore\b dumps, exit after the first test that fails,
    and do not remove the temporary directory \aunit\a\b.tmp\b.]
[l:local-fs?Force \aunit\a\b.tmp\b to be in a local filesystem.]
[o:pipe-output?Repeat each test with the standard output redirected through
    a pipe.]
[p:pipe-io?Repeat each test with the standard input and standard output
    redirected through pipes.]
[q:quiet?Output information on \bFAILED\b tests only.]
[r!:regular?Run each test with the standard input and standard output
    redirected through regular files.]
[t:test?Run only tests matching \apattern\a. Tests are numbered and
    consist of at least two digits (0 filled if necessary.) Tests matching
    \b+(0)\b are always run.]:[pattern]
[x:trace?Enable debug tracing.]
[v:verbose?List differences between actual (<) and expected (>) output,
    errors and exit codes. Also disable long output line truncation.]

unit [ command [ arg ... ] ]

[+INPUT FILES?The regression test file \aunit\a\b.tst\b is a \bksh\b(1)
    script that is executed in an environment with the following functions
    defined:]
    {
        [+BODY \b{ ... }?Defines the test body; used for complex tests.]
        [+CD \b\adirectory\a?Create and change to working directory for
            one test.]
        [+CLEANUP \b\astatus\a?Called at exit time to remove the
            temporary directory \aunit\a\b.tmp\b, list the tests totals via
            \bTALLY\b, and exit with status \astatus\a.]
        [+COMMAND \b\aarg\a ...?Runs the current command under test with
            \aarg\a ... appended to the default args.]
        [+CONTINUE?The background job must be running.]
        [+COPY \b\afrom to\a?Copy file \afrom\a to \ato\a. \afrom\a may
            be a regular file or \bINPUT\b, \bOUTPUT\b or \bERROR\b. Post
            test comparisons are still done for \afrom\a.]
        [+DIAGNOSTICS \b[ \b1\b | \b0\b | \apattern\a ]]?No argument or an
	    argument of \b1\b declares that diagnostics are to expected for
	    the remainder of the current \bTEST\b; \b0\b reverts to the default
            state that diagnostics are not expected; otherwise the argument
	    is a \bksh\b(1) pattern that must match the non-empty contents
	    of the standard error.]
        [+DO \b\astatement\a?Defines additional statements to be executed
            for the current test. \astatement\a may be a { ... } group.]
        [+EMPTY \bINPUT|OUTPUT|ERROR|SAME?The corresponding file is
            expected to be empty.]
        [+ERROR \b[ \b-e\b \afilter\a ]] [ \b-n\b ]] \afile\a | - \adata\a ...?The
	    standard error is expected to match either the contents
	    of \afile\a or the line \adata\a. \bERROR -n\b does not
	    append a newline to \adata\a. \afilter\a is a shell command
	    or pipeline that reads standard input and writes standard
	    output that is applied to ERROR before comparison with the
	    expected contents.]
        [+EXEC \b[ \aarg\a ... ]]?Runs the command under test with
            optional arguments. \bINPUT\b, \bOUTPUT\b, \bERROR\b, \bEXIT\b
            and \bSAME\b calls following this \bEXEC\b up until the next
            \bEXEC\b or the end of the script provide details for the
            expected results. If no arguments are specified then the
            arguments from the previious \bEXEC\b in the current \bTEST\b
            group are used, or no arguments if this is the first \bEXEC\b
            in the group.]
        [+EXIT \b\astatus\a?The command exit status is expected to match
            the pattern \astatus\a.]
        [+EXITED?The background job must have exited.]
        [+EXPORT \b[-]] \aname\a=\avalue\a ...?Export environment
            variables for one test.]
        [+FATAL \b\amessage\a ...?\amessage\a is printed on the standard
            error and \bregress\b exits with status \b1\b.]
        [+FIFO \bINPUT|OUTPUT|ERROR\b [ \b-n\b ]] \afile\a | - \adata\a ...?The
	    \bIO\B file is a fifo.]
        [+IF \b\acommand\a [\anote\a]]?If the \bsh\b(1) \acommand\a exits
            0 then tests until the next \bELIF\b, \bELSE\b or \bFI\b are
            enabled. Otherwise those tests are skipped. \bIF\b ... \bFI\b
            may be nested, but must not cross \bTEST\b boundaries. \anote\a
            is listed on the standard error if the correspoding test block
            is enabled; \bIF\b, \bELIF\b, \bELSE\b may nave a \anote\a
            operand.]
        [+IGNORE \b\afile\a ...?\afile\a is ignored for subsequent result
            comparisons. \afile\a may be \bOUTPUT\b or \bERROR\b.]
        [+IGNORESPACE?Ignore space differences when comparing expected
            output.]
        [+INCLUDE \b\afile\a ...?One or more \afile\a operands are read
            via the \bksh\b(1) \b.\b(1) command. \bVIEW\b is used to locate
            the files.]
        [+INFO \b\adescription\a?\adescription\a is printed on the
            standard error.]
        [+INITIALIZE?Called by \bregress\b to initialize a each
            \bTEST\b group.]
        [+INPUT \b[ \b-e\b \afilter\a ]] [ \b-n\b ]] \afile\a | - \adata\a ...?The
	    standard input is set to either the contents of \afile\a
	    or the line \adata\a. \bINPUT -n\b does not append a newline
	    to \adata\a. \afilter\a is a shell command or pipeline that
	    reads standard input and writes standard output that is
	    applied to OUTPUT before comparison with the expected contents.]
        [+INTRO?Called by \bregress\b to introduce all \bTEST\b
            groups.]
        [+IO \b[ \bFIFO\b | \bPIPE\b ]] \bINPUT|OUTPUT|ERROR\b [ \b-e\b \afilter\a ]] [ \b-n\b ]] \afile\a | - \adata\a ...?Internal
            support for the \bINPUT\b, \bOUTPUT\b and \bERROR\b functions.]
        [+JOB \b\aop\a [ ... ]]?Like \bEXEC\b except the command is run
            as a background job for the duration of the group or until it
            is killed via \bKILL\b.]
        [+KEEP \b\apattern\a ...?The temporary directory is cleared for
            each test. Files matching \apattern\a are retained between
            tests.]
        [+KILL \b[ \asignal\a ]]?Kill the background job with \asignal\a
        [ \bSIGKILL\b ]].]
        [+MOVE \b\afrom to\a?Rename file \afrom\a to \ato\a. \afrom\a may
            be a regular file or \bINPUT\b, \bOUTPUT\b or \bERROR\b. Post
            test comparisons are ignored for \afrom\a.]
        [+NOTE \b\acomment\a?\acomment\a is added to the current test
            trace output.]
        [+OUTPUT \b[ \b-e\b \afilter\a ]] [ \b-n\b ]] \afile\a | - \adata\a ...?The
	    standard output is expected to match either the contents
	    of \afile\a or the line \adata\a. \bOUTPUT -n\b does not
	    append a newline to \adata\a. \afilter\a is a shell command
	    or pipeline that reads standard input and writes standard
	    output that is applied to ERROR before comparison with the
	    expected contents.]
        [+PIPE \bINPUT|OUTPUT|ERROR\b [ \b-n\b ]] \afile\a | - \adata\a ...?The
	    \bIO\B file is a pipe.]
        [+PROG \b\acommand\a [ \aarg\a ... ]]?\acommand\a is run with
            optional arguments.]
        [+REMOVE \b\afile\a ...?\afile\a ... are removed after the
            current test is done.]
        [+RUN?Called by \bregress\b to run the current test.]
        [+SAME \b\anew old\a?\anew\a is expected to be the same as
            \aold\a after the current test completes.]
        [+SET \b[\bno\b]]\aname\a[=\avalue\a]]?Set the command line
            option --\aname\a. The setting is in effect for all tests until
            the next explicit \bSET\b.]
        [+TALLY?Called by \bregress\b display the \bTEST\b results.]
        [+TEST \b\anumber\a [ \adescription\a ... ]]?Define a new test
            group labelled \anumber\a with optional \adescripion\a.]
        [+TITLE \b[+]] \atext\a?Set the \bTEST\b output title to
            \atext\a. If \b+\b is specified then \atext\a is appended to
            the default title. The default title is the test file base
            name, and, if different from the test file base name, the test
            unit base name.]
        [+TWD \b[ \adir\a ... ]]?Set the temporary test dir to \adir\a.
            The default is \aunit\a\b.tmp\b, where \aunit\a is the test
            input file sans directory and suffix. If \adir\a matches \b/*\b
            then it is the directory name; if \adir\a is non-null then the
            prefix \b${TMPDIR:-/tmp}\b is added; otherwise if \adir\a is
            omitted then
            \b${TMPDIR:-/tmp}/tst-\b\aunit\a-$$-$RANDOM.\b\aunit\a is
            used.]
        [+UMASK \b[ \amask\a ]]?Run subsequent tests with \bumask\b(1)
            \amask\a. If \amask\a is omitted then the original \bumask\b is
            used.]
        [+UNIT \b\acommand\a [ \aarg\a ... ]]?Define the command and
            optional default arguments to be tested. \bUNIT\b explicitly
            overrides the default command name derived from the test script
            file name. A \acommand\a operand with optional arguments
            overrides the \bUNIT\b \acommand\a and arguments, with the
            exception that if the \bUNIT\b \acommand\a is \b-\b or \b+\b
            the \bUNIT\b arguments are appended to the operand or default
            unit command and arguments.]
        [+VIEW \b\avar\a [ \afile\a ]]?\avar\a is set to the full
            pathname of \avar\a [ \afile\a ]] in the current \b$VPATH\b
            view if defined.]
    }
[+SEE ALSO?\bnmake\b(1), \bksh\b(1)]
'
	;;
*)	USAGE='ko:[[no]name[=value]]t:[test]v unit [path [arg ...]]'
	;;
esac

function FATAL # message
{
	print -r -u2 "$command: $*"
	GROUP=FINI
	exit 1
}

function EMPTY
{
	typeset i
	typeset -n ARRAY=$1
	for i in ${!ARRAY[@]}
	do	unset ARRAY[$i]
	done
}

function INITIALIZE # void
{
	typeset i j
	cd "$TWD"
	case $KEEP in
	"")	RM *
		;;
	*)	for i in *
		do	case $i in
			!($KEEP))	j="$j $i" ;;
			esac
		done
		case $j in
		?*)	RM $j ;;
		esac
		;;
	esac
	: >INPUT >OUTPUT.ex >ERROR.ex
	BODY=""
	COPY=""
	DIAGNOSTICS=""
	DONE=""
	ERROR=""
	EXIT=0
	IGNORE=""
	INIT=""
	INPUT=""
	MOVE=""
	OUTPUT=""
	EMPTY FILE
	EMPTY FILTER
	EMPTY SAME
	EMPTY TYPE
}

function INTRO
{
	typeset base command

	if	[[ ! $TEST_quiet ]]
	then	base=${REGRESS##*/}
		base=${base%.tst}
		command=${COMMAND##*/}
		command=${command%' '*}
		set -- $TITLE
		TITLE=
		case $1 in
		''|+)	if	[[ $command == $base ]]
			then	TITLE=$COMMAND
			else	TITLE="$COMMAND, $base"
			fi
			if	(( $# ))
			then	shift
			fi
			;;
		esac
		while	(( $# ))
		do	if	[[ $TITLE ]]
			then	TITLE="$TITLE, $1"
			else	TITLE="$1"
			fi
			shift
		done
		print -u2 "TEST	$TITLE"
	fi
}

function TALLY # extra message text
{
	typeset msg
	case $GROUP in
	INIT)	;;
	*)	msg="TEST	$TITLE, $TESTS test"
		case $TESTS in
		1)	;;
		*)	msg=${msg}s ;;
		esac
		msg="$msg, $ERRORS error"
		case $ERRORS in
		1)	;;
		*)	msg=${msg}s ;;
		esac
		if	(( $# ))
		then	msg="$msg, $*"
		fi
		print -u2 "$msg"
		GROUP=INIT
		TESTS=0
		ERRORS=0
		;;
	esac
}

function TITLE # text
{
	TITLE=$@
}

function UNWIND
{
	while	(( COND > 1 ))
	do	print -r -u2 "$command: line $LINE: no matching FI for IF on line ${COND_LINE[COND]}"
		(( COND-- ))
	done
	if	(( COND > 0 ))
	then	(( COND = 0 ))
		FATAL "line $LINE: no matching FI for IF on line ${COND_LINE[COND+1]}"
	fi
	if	[[ $JOBPID ]]
	then	if	[[ $JOBPID != 0 ]]
		then	kill -KILL $JOBPID 2>/dev/null
			wait
		fi
		JOBPID=
	fi
	JOBSTATUS=
	JOBOP=
	wait
}

function CLEANUP # status
{
	typeset note

	if	[[ $GROUP != INIT ]]
	then	if	[[ ! $TEST_keep ]]
		then	cd $SOURCE
			if	[[ $TEST_local ]]
			then	RM ${TEST_local}
			fi
			RM "$TWD"
		fi
		if	(( $1 )) && [[ $GROUP != FINI ]]
		then	note=terminated
		fi
	fi
	TALLY $note
	[[ $TEST_keep ]] || UNWIND
	exit $1
}

function RUN # [ op ]
{
	typeset i r=1
	[[ $UMASK != $UMASK_ORIG ]] && umask $UMASK_ORIG
#print -u2 AHA#$LINENO $0 GROUP=$GROUP ITEM=$ITEM FLUSHED=$FLUSHED JOBOP=$JOBOP
	case $GROUP in
	INIT)	RM "$TWD"
		if	[[ $TEST_local ]]
		then	TEST_local=${TMPDIR:-/tmp}/rt-$$/${TWD##*/}
			mkdir -p "$TEST_local" && ln -s "$TEST_local" "$TWD" || FATAL "$TWD": cannot create directory
			TEST_local=${TEST_local%/*}
		else	mkdir "$TWD" || FATAL "$TWD": cannot create directory
		fi
		cd "$TWD"
		TWD=$PWD
		: > rmu
		if	rm -u rmu >/dev/null 2>&1
		then	TEST_rmu=-u
		else	rm rmu
		fi
		if	[[ $UNIT ]]
		then	set -- "${ARGV[@]}"
			case $1 in
			""|[-+]*)
				UNIT $UNIT "${ARGV[@]}"
				;;
			*)	UNIT "${ARGV[@]}"
				;;
			esac
		fi
		INTRO
		;;
	FINI)	;;
	$TEST_select)
		if	[[ $ITEM == $FLUSHED ]]
		then	return 0
		fi
		FLUSHED=$ITEM
		if	(( COND_SKIP[COND] ))
		then	return 1
		fi
		((COUNT++))
		if	(( $ITEM <= $LASTITEM ))
		then	LABEL=$TEST#$COUNT
		else	LASTITEM=$ITEM
			LABEL=$TEST:$ITEM
		fi
		TEST_file=""
		exec >/dev/null
		for i in $INPUT
		do	case " $OUTPUT " in
			*" $i "*)
				if	[[ -f $i.sav ]]
				then	cp $i.sav $i
					COMPARE="$COMPARE $i"
				elif	[[ -f $i ]]
				then	cp $i $i.sav
					COMPARE="$COMPARE $i"
				fi
				;;
			esac
		done
		for i in $OUTPUT
		do	case " $COMPARE " in
			*" $i "*)
				;;
			*)	COMPARE="$COMPARE $i"
				;;
			esac
		done
		for i in $INIT
		do	$i $TEST INIT
		done
#print -u2 AHA#$LINENO $0 GROUP=$GROUP ITEM=$ITEM JOBOP=$JOBOP JOBPID=$JOBPID JOBSTATUS=$JOBSTATUS
		if	[[ $JOBPID != 0 && ( $JOBPID || $JOBSTATUS ) ]]
		then	if	[[ ! $TEST_quiet ]]
			then	print -nu2 "$LABEL"
			fi
			RESULTS
		elif	[[ $BODY ]]
		then	SHOW=$NOTE
			if	[[ ! $TEST_quiet ]]
			then	print -r -u2 "	$SHOW"
			fi
			for i in $BODY
			do	$i $TEST BODY
			done
		else	SHOW=
			if	[[ ${TYPE[INPUT]} == PIPE ]]
			then	if	[[ ${TYPE[OUTPUT]} == PIPE ]]
				then	if	[[ ! $TEST_quiet ]]
					then	print -nu2 "$LABEL"
					fi
					cat <$TWD/INPUT | COMMAND "${ARGS[@]}" | cat >$TWD/OUTPUT
					RESULTS 'pipe input'
				else	if	[[ ! $TEST_quiet ]]
					then	print -nu2 "$LABEL"
					fi
					cat <$TWD/INPUT | COMMAND "${ARGS[@]}" >$TWD/OUTPUT
					RESULTS 'pipe io'
				fi
			elif	[[ ${TYPE[OUTPUT]} == PIPE ]]
			then	if	[[ ! $TEST_quiet ]]
				then	print -nu2 "$LABEL"
				fi
				COMMAND "${ARGS[@]}" <$TWD/INPUT | cat >$TWD/OUTPUT
				RESULTS 'pipe output'
			else	if	[[ $TEST_regular ]]
				then	if	[[ ! $TEST_quiet ]]
					then	print -nu2 "$LABEL"
					fi
					if	[[ ${TYPE[INPUT]} == FIFO ]]
					then	COMMAND "${ARGS[@]}" >$TWD/OUTPUT
					else	COMMAND "${ARGS[@]}" <$TWD/INPUT >$TWD/OUTPUT
					fi
					RESULTS
				fi
				if	[[ $TEST_pipe_input ]]
				then	if	[[ ! $TEST_quiet ]]
					then	print -nu2 "$LABEL"
					fi
					(trap '' PIPE; cat <$TWD/INPUT 2>/dev/null; exit 0) | COMMAND "${ARGS[@]}" >$TWD/OUTPUT
					STATUS=$?
					RESULTS 'pipe input'
				fi
				if	[[ $TEST_pipe_output ]]
				then	if	[[ ! $TEST_quiet ]]
					then	print -nu2 "$LABEL"
					fi
					COMMAND "${ARGS[@]}" <$TWD/INPUT | cat >$TWD/OUTPUT
					STATUS=$?
					RESULTS 'pipe output'
				fi
				if	[[ $TEST_pipe_io ]]
				then	if	[[ ! $TEST_quiet ]]
					then	print -nu2 "$LABEL"
					fi
					(trap '' PIPE; cat <$TWD/INPUT 2>/dev/null; exit 0) | COMMAND "${ARGS[@]}" | cat >$TWD/OUTPUT
					STATUS=$?
					RESULTS 'pipe io'
				fi
			fi
			set -- $COPY
			COPY=""
			while	:
			do	case $# in
				0|1)	break ;;
				*)	cp $1 $2 ;;
				esac
				shift 2
			done
			set -- $MOVE
			MOVE=""
			while	(( $# > 1 ))
			do	mv $1 $2
				shift 2
			done
		fi
		for i in $DONE
		do	$i $TEST DONE $STATUS
		done
		COMPARE=""
		r=0
		;;
	esac
	if	[[ $COMMAND_ORIG ]]
	then	COMMAND=$COMMAND_ORIG
		COMMAND_ORIG=
		ARGS=(${ARGS_ORIG[@]})
	fi
	return $r
}

function DO # cmd ...
{
	[[ $GROUP == $TEST_select ]] || return 1
	(( COND_SKIP[COND] )) && return 1
	[[ $UMASK != $UMASK_ORIG ]] && umask $UMASK
	return 0
}

function UNIT # cmd arg ...
{
	typeset cmd=$1
	case $cmd in
	[-+])	shift
		if	(( UNIT_READONLY ))
		then	COMMAND="$COMMAND $*"
		else	#BUG# ARGV=("${ARGV[@]}" "$@")
			set -- "${ARGV[@]}" "$@"
			ARGV=("$@")
		fi
		return
		;;
	esac
	(( UNIT_READONLY )) && return
	if	[[ $UNIT ]] && (( $# <= 1 ))
	then	set -- "${ARGV[@]}"
		case $1 in
		"")	set -- "$cmd" ;;
		[-+]*)	set -- "$cmd" "${ARGV[@]}" ;;
		*)	cmd=$1 ;;
		esac
	fi
	UNIT=
	COMMAND=$cmd
	shift
	typeset cmd=$(whence $COMMAND)
	if	[[ ! $cmd ]]
	then	FATAL $COMMAND: not found
	elif	[[ ! $cmd ]]
	then	FATAL $cmd: not found
	fi
	case $# in
	0)	;;
	*)	COMMAND="$COMMAND $*" ;;
	esac
}

function TWD # [ dir ]
{
	case $1 in
	'')	TWD=${TWD##*/}; TWD=${TMPDIR:-/tmp}/tst-${TWD%.*}-$$-$RANDOM ;;
	/*)	TWD=$1 ;;
	*)	TWD=${TMPDIR:-/tmp}/$1 ;;
	esac
}

function TEST # number description arg ...
{
	RUN
	LINE=$TESTLINE
	UNWIND
	COUNT=0
	LASTITEM=0
	case $1 in
	-)		((LAST++)); TEST=$LAST ;;
	+([0123456789]))	LAST=$1 TEST=$1 ;;
	*)		LAST=0${1/[!0123456789]/} TEST=$1 ;;
	esac
	NOTE=
	if	[[ ! $TEST_quiet && $TEST == $TEST_select ]] && (( ! COND_SKIP[COND] ))
	then	print -r -u2 "$TEST	$2"
	fi
	unset ARGS
	unset EXPORT
	EXPORTS=0
	TEST_file=""
	if	[[ $TEST != ${GROUP}* ]]
	then	GROUP=${TEST%%+([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ])}
		if	[[ $GROUP == $TEST_select ]] && (( ! COND_SKIP[COND] ))
		then	INITIALIZE
		fi
	fi
	((SUBTESTS=0))
	[[ $TEST == $TEST_select ]] && (( ! COND_SKIP[COND] ))
}

function EXEC # arg ...
{
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	if	((SUBTESTS++))
	then	RUN
	fi
	case $# in
	0)	set -- "${ARGS[@]}" ;;
	esac
	ITEM=$LINE
	NOTE="$(print -r -f '%q ' -- $COMMAND_ORIG "$@")${JOBPID:+&}"
	ARGS=("$@")
}

function JOB # arg ...
{
	JOBPID=0
	EXEC "$@"
}

function CONTINUE
{
	RUN || return
	JOBOP=CONTINUE
	ITEM=$LINE
	NOTE="$(print -r -f '%q ' -- $JOBOP)"
#print -u2 AHA#$LINENO JOBOP=$JOBOP ITEM=$ITEM NOTE=$NOTE
}

function EXITED
{
	RUN || return
	JOBOP=EXITED
	ITEM=$LINE
	NOTE="$(print -r -f '%q ' -- $JOBOP)"
#print -u2 AHA#$LINENO JOBOP=$JOBOP ITEM=$ITEM NOTE=$NOTE
}

function KILL # [ signal ]
{
	RUN || return
	JOBOP=$2
	[[ $JOBOP ]] || JOBOP=KILL
	ITEM=$LINE
	NOTE="$(print -r -f '%q ' -- $JOBOP)"
}

function CD
{
	RUN
	if	[[ $GROUP == $TEST_select ]] && (( ! COND_SKIP[COND] ))
	then	mkdir -p "$@" && cd "$@" || FATAL cannot initialize working directory "$@"
	fi
}

function EXPORT
{
	typeset x n v
	if	[[ $GROUP == INIT ]]
	then	for x
		do	n=${x%%=*}
			v=${x#*=}
			ENVIRON[ENVIRONS++]=$n="'$v'"
		done
	else	RUN
		if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
		then	return
		fi
		for x
		do	n=${x%%=*}
			v=${x#*=}
			EXPORT[EXPORTS++]=$n="'$v'"
		done
	fi
}

function FLUSH
{
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	if	((SUBTESTS++))
	then	RUN
	fi
}

function PROG # cmd arg ...
{
	typeset command args
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	ITEM=$LINE
	NOTE="$(print -r -f '%q ' -- "$@")"
	COMMAND_ORIG=$COMMAND
	COMMAND=$1
	shift
	ARGS_ORIG=(${ARGS[@]})
	ARGS=("$@")
}

function NOTE # description
{
	NOTE=$*
}

function IO # [ PIPE ] INPUT|OUTPUT|ERROR [-f*|-n] file|- data ...
{
	typeset op i v f file type x
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	[[ $UMASK != $UMASK_ORIG ]] && umask $UMASK_ORIG
	while	:
	do	case $1 in
		FIFO|PIPE)	type=$1; shift ;;
		*)		break ;;
		esac
	done
	op=$1
	shift
	[[ $type ]] && TYPE[$op]=$type
	FILTER[$op]=
	file=$TWD/$op
	while	:
	do	case $1 in
		-x)	x=1
			shift
			;;
		-e)	(( $# > 1 )) && shift
			FILTER[$op]=$1
			shift
			;;
		-e*)	FILTER[$op]=${1#-e}
			shift
			;;
		-f*|-n)	f=$1
			shift
			;;
		*)	break
			;;
		esac
	done
	case $# in
	0)	;;
	*)	case $1 in
		-)	;;
		*)	file=$1
			eval i='$'$op
			case " $i " in
			*" $file "*)
				;;
			*)	eval $op='"$'$op' $file"'
				;;
			esac
			;;
		esac
		shift
		;;
	esac
	case " $IGNORE " in
	*" $file "*)
		for i in $IGNORE
		do	case $i in
			$file)	;;
			*)	v="$v $i" ;;
			esac
		done
		IGNORE=$v
		;;
	esac
	FILE[$op]=$file
	case $op in
	OUTPUT|ERROR)
		file=$file.ex
		if	[[ $file != /* ]]
		then	file=$TWD/$file
		fi
		;;
	esac
	#unset SAME[$op]
	SAME[$op]=
	if	[[ $file == /* ]]
	then	RM $file.sav
	else	RM $TWD/$file.sav
	fi
	if	[[ $file == */* ]]
	then	mkdir -p ${file%/*}
	fi
	if	[[ $file != */ ]]
	then	if	[[ $type == FIFO ]]
		then	rm -f $file
			mkfifo $file
		fi
		if	[[ ${TYPE[$op]} != FIFO ]]
		then	if	[[ $JOBOP ]]
			then	case $#:$f in
				0:)	;;
				*:-f)	printf -- "$@" ;;
				*:-f*)	printf -- "${f#-f}""$@" ;;
				*)	print $f -r -- "$@" ;;
				esac >> $file
			else	case $#:$f in
				0:)	;;
				*:-f)	printf -- "$@" ;;
				*:-f*)	printf -- "${f#-f}""$@" ;;
				*)	print $f -r -- "$@" ;;
				esac > $file
			fi
		elif	[[ $#:$f != 0: ]]
		then	case $#:$f in
			*:-f)	printf -- "$@" ;;
			*:-f*)	printf -- "${f#-f}""$@" ;;
			*)	print $f -r -- "$@" ;;
			esac >> $file &
		fi
		if	[[ $x ]]
		then	chmod +x $file
		fi
	fi
}

function INPUT # file|- data ...
{
	IO $0 "$@"
}

function COPY # from to
{
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	COPY="$COPY $@"
}

function MOVE # from to
{
	typeset f
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	for f
	do	case $f in
		INPUT|OUTPUT|ERROR)
			f=$TWD/$f
			;;
		/*)	;;
		*)	f=$PWD/$f
			;;
		esac
		MOVE="$MOVE $f"
	done
}

function SAME # new old
{
	typeset i file v
	if	[[ $GROUP != $TEST_select ]] || (( COND_SKIP[COND] ))
	then	return
	fi
	case $# in
	2)	case $1 in
		INPUT)	cat $2 > $1; return ;;
		esac
		SAME[$1]=$2
		file=$1
		COMPARE="$COMPARE $1"
		;;
	3)	SAME[$2]=$3
		file=$2
		eval i='$'$1
		case " $i " in
		*" $2 "*)
			;;
		*)	eval $1='"$'$1' $2"'
			;;
		esac
		COMPARE="$COMPARE $2"
		;;
	esac
	case " $IGNORE " in
	*" $file "*)
		for i in $IGNORE
		do	case $i in
			$file)	;;
			*)	v="$v $i" ;;
			esac
		done
		IGNORE=$v
		;;
	esac
}

function OUTPUT # file|- data ...
{
	IO $0 "$@"
}

function ERROR # file|- data ...
{
	IO $0 "$@"
}

function RM # rm(1) args
{
	if	[[ ! $TEST_rmu ]]
	then	chmod -R u+rwx "$@" >/dev/null 2>&1
	fi
	rm $TEST_rmu $TEST_rmflags "$@"
}

function REMOVE # file ...
{
	typeset i
	for i
	do	RM $i $i.sav
	done
}

function IGNORE # file ...
{
	typeset i
	for i
	do	case $i in
		INPUT|OUTPUT|ERROR)
			i=$TWD/$i
			;;
		esac
		case " $IGNORE " in
		*" $i "*)
			;;
		*)	IGNORE="$IGNORE $i"
			;;
		esac
	done
}

function KEEP # pattern ...
{
	typeset i
	for i
	do	case $KEEP in
		"")	KEEP="$i" ;;
		*)	KEEP="$KEEP|$i" ;;
		esac
	done
}

function DIAGNOSTICS # [ 1 | 0 ]
{
	case $#:$1 in
	0:|1:1)	DIAGNOSTICS=1
		EXIT='*'
		;;
	1:|1:0)	DIAGNOSTICS=""
		EXIT=0
		;;
	*)	DIAGNOSTICS=$1
		EXIT='*'
		;;
	esac
}

function IGNORESPACE
{
	: ${IGNORESPACE=-b}
}

function EXIT # status
{
	EXIT=$1
}

function INFO # info description
{
	typeset -R15 info=$1
	if	[[ ! $1 ]]
	then	info=no
	fi
	shift
	if	[[ ! $TEST_quiet ]]
	then	print -r -u2 "$info " "$@"
	fi
}

function COMMAND # arg ...
{
	typeset input
	((TESTS++))
	case " ${ENVIRON[*]} ${EXPORT[*]}" in
	*' 'LC_ALL=*)
		;;
	*' 'LC_+([A-Z])=*)
		EXPORT[EXPORTS++]="LC_ALL="
		;;
	esac
	if	[[ $TEST_keep ]]
	then	(
		PS4=''
		set -x
		print -r -- "${ENVIRON[@]}" "${EXPORT[@]}" "PATH=$PATH" $COMMAND "$@"
		) 2>&1 >/dev/null |
		sed -e 's,^print -r -- ,,' -e 's,$, "$@",' >$TWD/COMMAND
		chmod +x $TWD/COMMAND
	fi
	if	[[ $UMASK != $UMASK_ORIG ]]
	then	: >$TWD/ERROR
		umask $UMASK
	fi
	if	[[ ${TYPE[INPUT]} == FIFO && ${FILE[INPUT]} == */INPUT ]]
	then	input="< ${FILE[INPUT]}"
	fi
	if	[[ $TEST_trace ]]
	then	set +x
		eval print -u2 "$PS4" "${ENVIRON[@]}" "${EXPORT[@]}" PATH='$PATH' '$'COMMAND '"$@"' '$input' '"2>$TWD/ERROR"' '"${JOBPID:+&}"'
	fi
	eval "${ENVIRON[@]}" "${EXPORT[@]}" PATH='$PATH' '$'COMMAND '"$@"' $input "2>$TWD/ERROR" "${JOBPID:+&}"
	STATUS=$?
	[[ $TEST_trace ]] && set -x
	if	[[ $JOBPID ]]
	then	JOBPID=$!
	fi
	[[ $UMASK != $UMASK_ORIG ]] && umask $UMASK_ORIG
	return $STATUS
}

function RESULTS # pipe*
{
	typeset i j k s failed ignore io op
	if	[[ $1 ]]
	then	io="$1 "
	fi
	[[ $JOBOP || $JOBPID || $JOBSTATUS ]] && sleep 1
	for i in $COMPARE $TWD/OUTPUT $TWD/ERROR
	do	case " $IGNORE $ignore $MOVE " in
		*" $i "*)	continue ;;
		esac
		ignore="$ignore $i"
		op=${i##*/}
		if	[[ ${FILTER[$op]} ]]
		then	eval "{ ${FILTER[$op]} ;} < $i > $i.fi"
			mv $i.fi $i
		fi
		j=${SAME[$op]}
		if	[[ ! $j ]]
		then	if	[[ $i == /* ]]
			then	k=$i
			else	k=$TWD/$i
			fi
			for s in ex sav err
			do	[[ -f $k.$s ]] && break
			done
			j=$k.$s
		fi
		if	[[ "$DIAGNOSTICS" && $i == */ERROR ]]
		then	if	[[ $STATUS == 0 && ! -s $TWD/ERROR || $DIAGNOSTICS != 1 && $(<$i) != $DIAGNOSTICS ]]
			then	failed=$failed${failed:+,}DIAGNOSTICS
				if	[[ $TEST_verbose && $DIAGNOSTICS != 1 ]]
				then	print -u2 "	===" "diagnostic pattern '$DIAGNOSTICS' did not match" ${i#$TWD/} "==="
					cat $i >&2
				fi
			fi
			continue
		fi
		diff $IGNORESPACE $i $j >$i.diff 2>&1
		if	[[ -s $i.diff ]]
		then	failed=$failed${failed:+,}${i#$TWD/}
			if	[[ $TEST_verbose ]]
			then	print -u2 "	===" diff $IGNORESPACE ${i#$TWD/} "<actual >expected ==="
				cat $i.diff >&2
			fi
		fi
	done
	if	[[ $JOBOP ]]
	then	if	[[ $JOBPID ]] && ! kill -0 $JOBPID 2>/dev/null
		then	wait $JOBPID
			JOBSTATUS=$?
			JOBPID=
		fi
#print -u2 AHA#$LINENO JOBOP=$JOBOP JOBPID=$JOBPID JOBSTATUS=$JOBSTATUS
		case $JOBOP in
		CONTINUE)
			if	[[ ! $JOBPID ]]
			then	failed=$failed${failed:+,}EXITED
			fi
			;;
		EXITED) if	[[ $JOBPID ]]
			then	failed=$failed${failed:+,}RUNNING
			fi
			;;
		*)	if	[[ ! $JOBPID ]]
			then	failed=$failed${failed:+,}EXITED
			fi
			if	! kill -$JOBOP $JOBPID 2>/dev/null
			then	failed=$failed${failed:+,}KILL-$JOBOP
			fi
			;;
		esac
		JOBOP=
	fi
	if	[[ ! $failed && $STATUS != $EXIT ]]
	then	failed="exit code $EXIT expected -- got $STATUS"
	fi
	if	[[ $failed ]]
	then	((ERRORS++))
		if	[[ ! $TEST_quiet ]]
		then	SHOW="FAILED ${io}[ $failed ] $NOTE"
			print -r -u2 "	$SHOW"
		fi
		if	[[ $TEST_keep ]]
		then	GROUP=FINI
			exit
		fi
	elif	[[ ! $TEST_quiet ]]
	then	SHOW=$NOTE
		print -r -u2 "	$SHOW"
	fi
}

function SET # [no]name[=value]
{
	typeset i r
	if	[[ $TEST ]]
	then	RUN
	fi
	for i
	do	if	[[ $i == - ]]
		then	r=1
		elif	[[ $i == + ]]
		then	r=
		else	if	[[ $i == no?* ]]
			then	i=${i#no}
				v=
			elif	[[ $i == *=* ]]
			then	v=${i#*=}
				if	[[ $v == 0 ]]
				then	v=
				fi
				i=${i%%=*}
			else	v=1
			fi
			i=${i//-/_}
			if	[[ $r ]]
			then	READONLY[$i]=1
			elif	[[ ${READONLY[$i]} ]]
			then	continue
			fi
			eval TEST_$i=$v
		fi
	done
}

function VIEW # var [ file ]
{
	nameref var=$1
	typeset i bwd file pwd view root offset
	if	[[ $var ]]
	then	return 0
	fi
	case $# in
	1)	file=$1 ;;
	*)	file=$2 ;;
	esac
	pwd=${TWD%/*}
	bwd=${PMP%/*}
	if	[[ -r $file ]]
	then	if	[[ ! -d $file ]]
		then	var=$PWD/$file
			return 0
		fi
		for i in $file/*
		do	if	[[ -r $i ]]
			then	var=$PWD/$file
				return 0
			fi
			break
		done
	fi
	for view in ${VIEWS[@]}
	do	case $view in
		/*)	;;
		*)	view=$pwd/$view ;;
		esac
		case $offset in
		'')	case $pwd in
			$view/*)	offset=${pwd#$view} ;;
			*)		offset=${bwd#$view} ;;
			esac
			;;
		esac
		if	[[ -r $view$offset/$file ]]
		then	if	[[ ! -d $view$offset/$file ]]
			then	var=$view$offset/$file
				return 0
			fi
			for i in $view$offset/$file/*
			do	if	[[ -f $i ]]
				then	var=$view$offset/$file
					return 0
				fi
				break
			done
		fi
	done
	var=
	return 1
}

function INCLUDE # file ...
{
	typeset f v x
	for f
	do	if	VIEW v $f || [[ $PREFIX && $f != /* ]] && VIEW v $PREFIX$f
		then	x=$x$'\n'". $v"
		else	FATAL $f: not found
		fi
	done
	[[ $x ]] && trap "$x" 0
}

function UMASK # [ mask ]
{
	if	(( $# ))
	then	UMASK=$1
	else	UMASK=$UMASK_ORIG
	fi
}

function PIPE # INPUT|OUTPUT|ERROR file|- data ...
{
	IO $0 "$@"
}

function FIFO # INPUT|OUTPUT|ERROR file|- data ...
{
	IO $0 "$@"
}

function IF # command(s) [note]
{
	[[ $GROUP == $TEST_select ]] || return
	RUN
	(( COND++ ))
	COND_LINE[COND]=$LINE
	if	(( COND > 1 && COND_SKIP[COND-1] ))
	then	(( COND_KEPT[COND] = 1 ))
		(( COND_SKIP[COND] = 1 ))
	elif	eval "{ $1 ;} >/dev/null 2>&1"
	then	(( COND_KEPT[COND] = 1 ))
		(( COND_SKIP[COND] = 0 ))
		[[ $2 && ! $TEST_quiet ]] && print -u2 "NOTE	$2"
	else	(( COND_KEPT[COND] = 0 ))
		(( COND_SKIP[COND] = 1 ))
	fi
}

function ELIF # command(s) [note]
{
	[[ $GROUP == $TEST_select ]] || return
	RUN
	if	(( COND <= 0 ))
	then	FATAL line $LINE: no matching IF for ELIF
	fi
	if	(( COND_KEPT[COND] ))
	then	(( COND_SKIP[COND] = 0 ))
	elif	eval "$* > /dev/null 2>&1"
	then	(( COND_KEPT[COND] = 1 ))
		(( COND_SKIP[COND] = 0 ))
		[[ $2 && ! $TEST_quiet ]] && print -u2 "NOTE	$2"
	else	(( COND_SKIP[COND] = 1 ))
	fi
}

function ELSE # [note]
{
	[[ $GROUP == $TEST_select ]] || return
	RUN
	if	(( COND <= 0 ))
	then	FATAL line $LINE: no matching IF for ELSE
	fi
	if	(( COND_KEPT[COND] ))
	then	(( COND_SKIP[COND] = 1 ))
	else	(( COND_KEPT[COND] = 1 ))
		(( COND_SKIP[COND] = 0 ))
		[[ $1 && ! $TEST_quiet ]] && print -u2 "NOTE	$1"
	fi
}

function FI
{
	[[ $GROUP == $TEST_select ]] || return
	RUN
	if	(( COND <= 0 ))
	then	FATAL line $LINE: no matching IF for FI on line $LINE
	fi
	(( ! COND_KEPT[COND] )) && [[ $1 && ! $TEST_quiet ]] && print -u2 "NOTE	$1"
	(( COND-- ))
}

# main

integer ERRORS=0 ENVIRONS=0 EXPORTS=0 TESTS=0 SUBTESTS=0 LINE=0 TESTLINE=0
integer ITEM=0 LASTITEM=0 COND=0 UNIT_READONLY=0 COUNT
typeset ARGS COMMAND COPY DIAGNOSTICS ERROR EXEC FLUSHED=0 GROUP=INIT
typeset IGNORE INPUT KEEP OUTPUT TEST SOURCE MOVE NOTE UMASK UMASK_ORIG
typeset ARGS_ORIG COMMAND_ORIG TITLE UNIT ARGV PREFIX OFFSET IGNORESPACE
typeset COMPARE MAIN JOBPID='' JOBSTATUS=''
typeset TEST_file TEST_keep TEST_pipe_input TEST_pipe_io TEST_pipe_output TEST_local
typeset TEST_quiet TEST_regular=1 TEST_rmflags='-rf --' TEST_rmu TEST_select

typeset -A SAME VIEWS FILE TYPE READONLY FILTER
typeset -a COND_LINE COND_SKIP COND_KEPT ENVIRON EXPORT
typeset -Z LAST=00

unset FIGNORE

while	getopts -a $command "$USAGE" OPT
do	case $OPT in
	b)	(( $OPTARG )) && IGNORESPACE=-b
		;;
	i)	SET - pipe-input=$OPTARG
		;;
	k)	SET - keep=$OPTARG
		;;
	l)	SET - local
		;;
	o)	SET - pipe-output=$OPTARG
		;;
	p)	SET - pipe-io=$OPTARG
		;;
	q)	SET - quiet=$OPTARG
		;;
	r)	SET - regular=$OPTARG
		;;
	t)	if	[[ $TEST_select ]]
		then	TEST_select="$TEST_select|${OPTARG//,/\|}"
		else	TEST_select="${OPTARG//,/\|}"
		fi
		;;
	x)	SET - trace=$OPTARG
		;;
	v)	SET - verbose=$OPTARG
		;;
	*)	GROUP=FINI
		exit 2
		;;
	esac
done
shift $OPTIND-1
case $# in
0)	FATAL test unit name omitted ;;
esac
export COLUMNS=80
SOURCE=$PWD
PATH=$SOURCE:${PATH#?(.):}
PATH=${PATH%%:?(.)}:/bin:/usr/bin
UNIT=$1
shift
if	[[ -f $UNIT && ! -x $UNIT ]]
then	REGRESS=$UNIT
else	REGRESS=${UNIT%.tst}
	REGRESS=$REGRESS.tst
	[[ -f $REGRESS ]] || FATAL $REGRESS: regression tests not found
fi
UNIT=${UNIT##*/}
UNIT=${UNIT%.tst}
MAIN=$UNIT
if	[[ $VPATH ]]
then	set -A VIEWS ${VPATH//:/' '}
	OFFSET=${SOURCE#${VIEWS[0]}}
	if	[[ $OFFSET ]]
	then	OFFSET=${OFFSET#/}/
	fi
fi
if	[[ $REGRESS == */* ]]
then	PREFIX=${REGRESS%/*}
	if	[[ ${#VIEWS[@]} ]]
	then	for i in ${VIEWS[@]}
		do	PREFIX=${PREFIX#$i/}
		done
	fi
	PREFIX=${PREFIX#$OFFSET}
	if	[[ $PREFIX ]]
	then	PREFIX=$PREFIX/
	fi
fi
TWD=$PWD/$UNIT.tmp
PMP=$(pwd -P)/$UNIT.tmp
UMASK_ORIG=$(umask)
UMASK=$UMASK_ORIG
ARGV=("$@")
if	[[ ${ARGV[0]} && ${ARGV[0]} != [-+]* ]]
then	UNIT "${ARGV[@]}"
	UNIT_READONLY=1
fi
trap 'code=$?; CLEANUP $code' EXIT
if	[[ ! $TEST_select ]]
then	TEST_select="[0123456789]*"
fi
TEST_select="@($TEST_select|+(0))"
if	[[ $TEST_trace ]]
then	export PS4=':$LINENO: '
	typeset -ft $(typeset +f)
	set -x
fi
if	[[ $TEST_verbose ]]
then	typeset SHOW
else	typeset -L70 SHOW
fi
if	[[ ! $TEST_keep ]] && (ulimit -c 0) >/dev/null 2>&1
then	ulimit -c 0
fi
set --pipefail

# some last minute shenanigans

alias BODY='BODY=BODY; function BODY'
alias CONTINUE='LINE=$LINENO; CONTINUE'
alias DO='(( $ITEM != $FLUSHED )) && RUN DO; DO &&'
alias DONE='DONE=DONE; function DONE'
alias EXEC='LINE=$LINENO; EXEC'
alias EXITED='LINE=$LINENO; EXITED'
alias INIT='INIT=INIT; function INIT'
alias JOB='LINE=$LINENO; JOB'
alias KILL='LINE=$LINENO; KILL'
alias PROG='LINE=$LINENO; FLUSH; PROG'
alias TEST='TESTLINE=$LINENO; TEST'
alias IF='LINE=$LINENO; FLUSH; IF'
alias ELIF='LINE=$LINENO; FLUSH; ELIF'
alias ELSE='LINE=$LINENO; FLUSH; ELSE'
alias FI='LINE=$LINENO; FLUSH; FI'

# do the tests

. $REGRESS
RUN
GROUP=FINI
