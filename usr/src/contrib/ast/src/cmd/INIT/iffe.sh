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
# Glenn Fowler & Phong Vo
# AT&T Research
#
# test if feature exists
# this script is written to make it through all sh variants
#
# NOTE: .exe a.out suffix and [\\/] in path patterns for dos/nt

case $-:$BASH_VERSION in
*x*:[0123456789]*)	: bash set -x is broken :; set +ex ;;
esac

command=iffe
version=2012-07-17 # update in USAGE too #

compile() # $cc ...
{
	"$@" 2>$tmp.err
	_compile_status=$?
	if	test -s $tmp.err
	then	cat $tmp.err >&2
		case $_compile_status in
		[1-9]|[1-9][0-9]|1[01][0-9]|12[0-7])
			if	egrep -i -c 'terminated with signal|core dump|segmentation fault' $tmp.err >&$nullout
			then	_compile_status=139
			fi
			;;
		esac
	fi
	case $_compile_status in
	?|??|1[01]?|12[0-8]|25?)
		;;
	*)	echo "$command: $@" >&$stderr
		cat $tmp.err >&$stderr
		echo "$command: $1: core dump or fatal interruption -- results inconclusive" >&$stderr
		exit $_compile_status
		;;
	esac
	return $_compile_status
}

is_hdr() # [ - ] [ file.c ] hdr
{
	case $1 in
	-)	_is_hdr_flag=-; shift ;;
	*)	_is_hdr_flag= ;;
	esac
	case $1 in
	*.c)	_is_hdr_file=$1; shift ;;
	*)	_is_hdr_file=$tmp.c ;;
	esac
	is hdr $1
	compile $cc -c $_is_hdr_file <&$nullin >&$nullout 2>$tmp.e
	_is_hdr_status=$?
	case $_is_hdr_status in
	0)	if	test -s $tmp.e
		then	case `grep '#.*error' $tmp.e` in
			?*)	_is_hdr_status=1 ;;
			esac
		fi
		;;
	esac
	case $_is_hdr_status in
	0)	success $_is_hdr_flag
		;;
	*)	case $debug in
		3)	cat $tmp.e >&$stderr ;;
		esac
		failure $_is_hdr_flag
		;;
	esac
	return $_is_hdr_status
}

pkg() # package
{
	case $1 in
	'')	pth=''
		case $pth in
		'')	pth="/bin /usr/bin" ;;
		*:*)	pth=`echo "$pth" | sed 's/:/ /g'` ;;
		esac
		return
		;;
	'<')	shift
		;;
	*)	return
		;;
	esac
	case $1 in
	X|X11*)	i="openwin"
		case $1 in
		X)	set X11 ;;
		esac
		case $1 in
		X11)	case $# in
			1)	set $1 6 5 4 ;;
			esac
			;;
		esac
		;;
	*)	i=
		;;
	esac
	pth="{ usr . - . contrib local $i - . share - . lib - $1"
	i=$1
	while	:
	do	shift
		case $# in
		0)	break ;;
		esac
		case $1 in
		'>')	shift; break ;;
		esac
		pth="$pth ${i}R$1 ${i}.$1"
	done
	pth="$pth . } $*"
}

is() # op name
{
	case $verbose in
	1)	case $complete in
		1)	failure ;;
		esac
		oo=$1
		shift
		case $1 in
		?*)	yy=is
			ii=$1
			complete=1
			case $oo in
			cmd)	mm="a command" ;;
			dat)	mm="a library data symbol" ;;
			dfn)	mm="a macro with extractable value" ;;
			exp)	mm="true" ;;
			hdr)	mm="a header" ;;
			id)	mm="an identifier" ;;
			lcl)	mm="a native header" ;;
			key)	mm="a reserved keyword" ;;
			lib)	mm="a library function" ;;
			LIB)	case $2 in
				"")	mm="a library" ;;
				*)	ii=$*; mm="a library group" ;;
				esac
				;;
			mac)	mm="a macro" ;;
			mem)	mm="a member of $2" ;;
			mth)	mm="a math library symbol" ;;
			nos)	mm="a non-opaque struct" ;;
			npt)	mm="a symbol that needs a prototype" ;;
			num)	mm="a numeric constant or enum" ;;
			nxt)	mm="an include path for the native header" ;;
			opt)	mm="set in \$PACKAGE_OPTIONS" ;;
			pth)	mm="a file" ;;
			run)	yy="capture output of" mm= ;;
			siz)	mm="a type with known size" ;;
			sym)	mm="a typed variable" ;;
			sys)	mm="a system header" ;;
			typ)	mm="a type or typedef" ;;
			val)	yy="determine" mm="value" ;;
			*)	yy= mm= ;;
			esac
			case $ii in
			[abcdefghijklmnopqrstuvwxyz]*[abcdefghijklmnopqrstuvwxyz]'{') ii="$ii ... }end" ;;
			esac
			$show "$command: test:" $yy $ii $mm "...$SHOW" >&$stderr
			complete=1
			;;
		esac
		;;
	esac
}

success()
{
	case $1 in
	-)	shift
		;;
	*)	case $result in
		UNKNOWN)	result=SUCCESS ;;
		esac
		case $1 in
		+)	return ;;
		esac
		;;
	esac
	case $complete:$verbose in
	1:1)	case $suspended in
		1)	suspended=0
			$show "$command: test:" $yy $ii $mm "...$SHOW" >&$stderr
			;;
		esac
		complete=0
		case $# in
		0)	mm="yes" ;;
		*)	mm="'$*'" ;;
		esac
		case $debug in
		0)	echo " $mm" >&$stderr ;;
		*)	echo "$command: ... $mm" >&$stderr ;;
		esac
		;;
	esac
}

failure()
{
	case $1 in
	-)	shift ;;
	*)	result=FAILURE
		case $1 in
		+)	return ;;
		esac
		;;
	esac
	case $complete:$verbose in
	1:1)	case $suspended in
		1)	suspended=0
			$show "$command: test:" $yy $ii $mm "...$SHOW" >&$stderr
			;;
		esac
		complete=0
		case $group in
		'')	case $# in
			0)	mm="no" ;;
			*)	mm=$* ;;
			esac
			;;
		*)	mm=
			;;
		esac
		case $debug in
		0)	echo " $mm" >&$stderr ;;
		*)	echo "$command: ... $mm" >&$stderr ;;
		esac
		;;
	esac
}

# report
#
#	-	ignore global status
#	-0	normal sense
#	-1	inverted sense if ! def
#	status	test status 0:success *:failure
#	success	success comment
#	failure	failure comment
#	default	default setting comment
#
#   globals
#
#	$not	invert test sense
# 	$M	test variable
#	$m	test macro
#	$v	default macro

report() # [-] [-0] [-1] status value success failure default
{
	case $1 in
	-)	_report_ignore=$1
		shift
		;;
	*)	_report_ignore=
		;;
	esac
	_report_not=$not
	case $1 in
	-0)	shift
		;;
	-1)	shift
		case $def in
		''|-)	case $_report_not in
			1)	_report_not= ;;
			*)	_report_not=1 ;;
			esac
			;;
		esac
		;;
	esac
	_report_status=$1
	case $_report_ignore:$_report_status in
	-:*)	;;
	*:0)	success $_report_ignore
		;;
	*)	failure $_report_ignore
		case $group in
		?*)	return ;;
		esac
		;;
	esac
	_report_value=$2
	case $_report_not in
	1)	case $_report_status in
		0)	_report_status=1 ;;
		*)	_report_status=0 ;;
		esac
		_report_success=$4
		_report_failure=$3
		;;
	*)	_report_success=$3
		_report_failure=$4
		;;
	esac
	_report_default=$5
	case $_report_status in
	0)	case $M in
		*-*)	;;
		*)	usr="$usr$nl#define $m $_report_value"
			case $_report_success in
			''|-)	;;
			*)	case $define in
				1)	echo "#define $m	$_report_value	/* $_report_success */" ;;
				n)	echo "$m=$_report_value"
				esac
				;;
			esac
			eval $m=\'$_report_value\'
			;;
		esac
		;;
	*)	case $M in
		*-*)	;;
		*)	case $_report_failure in
			''|-)	;;
			*)	case $define$all$config$undef in
				1?1?|1??1)echo "#undef	$m		/* $_report_failure */" ;;
				11??)	  echo "#define $m	0	/* $_report_failure */" ;;
				n1?1)	  echo "$m=" ;;
				n1??)	  echo "$m=0" ;;
				esac
				;;
			esac
			case $_report_default in
			''|-)	;;
			*)	case $define$set in
				1?*)	echo "#define $v	$set	/* $_report_default */" ;;
				n?*)	echo "$v=$set" ;;
				esac
				;;
			esac
			eval $m=0
			;;
		esac
		;;
	esac
}

noisy()
{
	case $complete:$verbose in
	1:1)	suspended=1
		echo >&$stderr
		;;
	esac
}

here_broken=0

literal() # line that echo might process
{
	if	cat <<!
$*
!
	then	: old here doc botch not present
	else	case $here_broken in
		0)	here_broken=1
			echo "$command: your shell botches here documents; this was fixed back in the 80's" >&$stderr
			;;
		esac
		sh -c "cat <<!
$*
!
"
	fi
}

copy() # "output-file" "data-that-must-not-be-processed-by-echo"
{
	case $1 in
	-)	case $shell in
		ksh)	print -r - "$2"
			;;
		*)	if	cat <<!
$2
!
			then	: ancient here doc botch not present
			else	case $here_broken in
				0)	here_broken=1
					echo "$command: your shell botches here documents; this was fixed back in the 80's" >&$stderr
					;;
				esac
				sh -c "cat <<!
$2
!
"
			fi
			;;
		esac
		;;
	*)	case $shell in
		ksh)	print -r - "$2" > "$1"
			;;
		*)	if	cat > "$1" <<!
$2
!
			then	: ancient here doc botch not present
			else	case $here_broken in
				0)	here_broken=1
					echo "$command: your shell botches here documents; this was fixed back in the 80's" >&$stderr
					;;
				esac
				sh -c "cat > \"$1\" <<!
$2
!
"
			fi
			;;
		esac
		;;
	esac
}

# verify that cc is a C compiler

checkcc()
{
	# check for local package root directories

	case $PACKAGE_PATH in
	?*)	for i in `echo $PACKAGE_PATH | sed 's,:, ,g'`
		do	if	test -d $i/include
			then	cc="$cc -I$i/include"
				occ="$occ -I$i/include"
			fi
			if	test -d $i/lib
			then	cc="$cc -L$i/lib"
				occ="$occ -L$i/lib"
				for y in $libpaths
				do	eval $y=\"\$$y:\$i/lib\$${y}_default\"
					eval export $y
				done
			fi
		done
		;;
	esac
	echo "int i = 1;" > $tmp.c
	if	compile $cc -c $tmp.c <&$nullin >&$nullout
	then	echo "(;" > $tmp.c
		if	compile $cc -c $tmp.c <&$nullin >&$nullout
		then	cctest="should not compile '(;'"
		fi
	else	cctest="should compile 'int i = 1;'"
	fi
	case $cctest in
	"")	cctest=0
		;;
	*)	echo "$command: $cc: not a C compiler: $cctest" >&$stderr
		exit 1
		;;
	esac
}

checkread()
{
	case $cctest in
	"")	checkcc ;;
	esac
	case $posix_read in
	-no)	;;
	*)	posix_read=`(read -r _checkread_line; echo $_checkread_line) 2>/dev/null <<!
a z
!
`
		;;
	esac
	case $posix_read in
	"a z")	posix_read=1
		;;
	*)	copy ${tmp}r.c "
		extern int read();
		extern int write();
		int main()
		{
			char	c;
			char	r;
			int	k;
			char	s[32];
			k = 0;
			while (read(0, &c, 1) == 1)
			{
				if (k >= 0)
				{
					if (c == ' ' || c == '\\t')
					{
						if (k < sizeof(s))
							s[k++] = c;
						continue;
					}
					if (k > 1 && c != '#' && c != '\\n' && c != '\\r')
						write(1, s + 1, k - 1);
					k = -1;
				}
				if (c == '\\r')
				{
					r = c;
					if (read(0, &c, 1) == 1 && c != '\\n')
						write(1, &r, 1);
				}
				write(1, &c, 1);
				if (c == '\\n')
					return 0;
			}
			return 1;
		}"
		if	compile $cc -o ${tmp}r.exe ${tmp}r.c >&$nullout
		then	posix_read=${tmp}r.exe
		else	echo "$command: cannot compile read -r workaround" >&$stderr
			exit 1
		fi
		;;
	esac
}

execute()
{
	case $verbose in
	0)	noteout=$nullout ;;
	*)	noteout=$stderr ;;
	esac
	if	test "" != "$cross"
	then	crossexec $cross "$@" 9>&$noteout
		_execute_=$?
	elif	test -d /NextDeveloper
	then	"$@" <&$nullin >&$nullout 9>&$noteout
		_execute_=$?
		"$@" <&$nullin | cat
	else	"$@" 9>&$noteout
		_execute_=$?
	fi
	return $_execute_
}

exclude()
{
	case $excludes in
	'')	return 0 ;;
	esac
	for _exclude_var
	do	eval _exclude_old=\$$_exclude_var
		case $_exclude_old in
		*" -I"*);;
		*)	continue ;;
		esac
		_exclude_new=
		_exclude_sep=
		for _exclude_arg in $_exclude_old
		do	_exclude_skip=
			for _exclude_dir in $excludes
			do	case $_exclude_arg in
				-I$_exclude_dir|-I*/$_exclude_dir)
					_exclude_skip=1
					break;
					;;
				esac
			done
			case $_exclude_skip in
			'')	_exclude_new="$_exclude_new$_exclude_sep$_exclude_arg"
				_exclude_sep=" "
				;;
			esac
		done
		eval $_exclude_var=\$_exclude_new
		case $debug in
		0)	;;
		*)	echo $command: exclude $_exclude_var: "$_exclude_old => $_exclude_new" >&$stderr
			;;
		esac
	done
}

all=0
apis=
binding="-dy -dn -Bdynamic -Bstatic -Wl,-ashared -Wl,-aarchive -call_shared -non_shared '' -static"
complete=0
config=0
defhdr=
define=1
explicit=0
iff=
usr=
cross=
debug=0
deflib=
dir=FEATURE
excludes=
executable="test -x"
exists="test -e"
gothdr=
gotlib=
idno=
idyes=
ifs=${IFS-'
	 '}
in=
includes=
intrinsic=
libpaths="LD_LIBRARY_PATH LD_LIBRARYN32_PATH LD_LIBRARY64_PATH LIBPATH SHLIB_PATH"
	LD_LIBRARY_PATH_default=:/lib:/usr/lib
	LD_LIBRARYN32_PATH_default=:/lib32:/usr/lib32
	LD_LIBRARY64_PATH_default=:/lib64:/usr/lib64
	LIBPATH_default=:/lib:/usr/lib
	SHLIB_PATH_default=:/shlib:/usr/shlib:/lib:/usr/lib
nl="
"
optimize=1
occ=cc
one=
out=
posix_read=-check
case `(set -f && set x * && echo $# && set +f) 2>/dev/null` in
2)	posix_noglob="set -f" posix_glob="set +f" ;;
*)	case `(set -F && set x * && echo $# && set +F) 2>/dev/null` in
	2)	posix_noglob="set -F" posix_glob="set +F" ;;
	*)	posix_noglob=":" posix_glob=":" ;;
	esac
	;;
esac
protoflags=
puthdr=
putlib=
pragma=
case $RANDOM in
$RANDOM)shell=bsh
	($executable .) 2>/dev/null || executable='test -r'
	($exists .) 2>/dev/null || exists='test -r'
	;;
*)	case $BASH_VERSION in
	?*)	shell=bash ;;
	*)	shell=ksh ;;
	esac
	;;
esac
reallystatic=
reallystatictest=
regress=
static=.
statictest=
case $COTEMP in
"")	case $HOSTNAME in
	""|?|??|???|????|????)
		tmp=${HOSTNAME}
		;;
	*)	case $shell in
		bsh)	eval `echo $HOSTNAME | sed 's/\\(....\\).*/tmp=\\1/'` ;;
		*)	eval 'tmp=${HOSTNAME%${HOSTNAME#????}}' ;;
		esac
		;;
	esac
	tmp=${tmp}$$
	;;
*)	tmp=x${COTEMP}
	;;
esac
COTEMP=${tmp}
export COTEMP
case $tmp in
./*)	;;
??????????*)
	case $shell in
	bsh)	eval `echo $tmp | sed 's/\\(.........\\).*/tmp=\\1/'` ;;
	*)	eval 'tmp=${tmp%${tmp#?????????}}' ;;
	esac
	;;
?????????)
	;;
????????)
	tmp=F$tmp
	;;
esac
case $tmp in
./*)	;;
*)	tmp=./$tmp ;;
esac
undef=0
verbose=0
vers=

# options -- `-' for output to stdout otherwise usage

case $1 in
-)	out=-; shift ;;
esac
set=

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	USAGE=$'
[-?
@(#)$Id: iffe (AT&T Research) 2012-07-17 $
]
'$USAGE_LICENSE$'
[+NAME?iffe - C compilation environment feature probe]
[+DESCRIPTION?\biffe\b is a command interpreter that probes the C
	compilation environment for features. A feature is any file, option
	or symbol that controls or is controlled by the C compiler. \biffe\b
	tests features by generating and compiling C programs and observing
	the behavior of the C compiler and generated programs.]
[+?\biffe\b statements are line oriented. Statements may appear in the
	operand list with the \b:\b operand or \bnewline\b as the line
	delimiter. The standard input is read if there are no command
	line statements or if \afile\a\b.iffe\b is omitted.]
[+?Though similar in concept to \bautoconf\b(1) and \bconfig\b(1), there
	are fundamental differences. The latter tend to generate global
	headers accessed by all components in a package, whereas \biffe\b is
	aimed at localized, self contained feature testing.]
[+?Output is generated in \bFEATURE/\b\atest\a by default, where \atest\a is
	the base name of \afile\a\b.iffe\b or the \biffe\b \brun\b
	file operand. Output is first generated in a temporary file; the
	output file is updated if it does not exist or if the temporary file
	is different. If the first operand is \b-\b then the output is written
	to the standard output and no update checks are done.]
[+?Files with suffixes \b.iffe\b and \b.iff\b are assumed to contain
	\biffe\b statements.]
[a:all?Define failed test macros \b0\b. By default only successful test macros
	are defined \b1\b.]
[c:cc?Sets the C compiler name and flags to be used in the feature
	tests.]:[C-compiler-name [C-compiler-flags ...]]]
[C:config?Generate \bconfig\b(1) style \aHAVE_\a* macro names. This implies
	\b--undef\b. Since \bconfig\b(1) has inconsistent naming conventions,
	the \bexp\b op may be needed to translate from the (consistent)
	\biffe\b names. Unless otherwise noted a \bconfig\b macro name
	is the \biffe\b macro name prefixed with \bHAVE\b and converted to
	upper case. \b--config\b is set by default if the command arguments
	contain a \brun\b op on an input file with the base name \bconfig\b.]
[d:debug?Sets the debug level. Level 0 inhibits most
	error messages, level 1 shows compiler messages, and
	level 2 traces internal \biffe\b \bsh\b(1) actions and does
	not remove core dumps on exit.]#[level]
[D:define?Successful test macro definitions are emitted. This is the default.]
[E:explicit?Disable implicit test output.]
[F:features?Sets the feature test header to \ahdr\a.  This header typically
        defines *_SOURCE feature test macros.]:[hdr:=NONE]
[i:input?Sets the input file name to \afile\a, which
	must contain \biffe\b statements.]:[file]
[I:include?Adds \b-I\b\adir\a to the C compiler flags.]:[dir]
[L:library?Adds \b-L\b\adir\a to the C compiler flags.]:[dir]
[n:name-value?Output \aname\a=\avalue\a assignments only.]
[N!:optimize?\b--nooptimize\b disables compiler optimization options.]
[o:output?Sets the output file name to \afile\a.]:[file]
[O:stdio?Sets the standard io header to \ahdr\a.]:[hdr:=stdio.h]
[e:package?Sets the \bproto\b(1) package name to \aname\a.]:[name]
[p:prototyped?Emits \b#pragma prototyped\b at the top of the
	output file. See \bproto\b(1).]
[P:pragma?Emits \b#pragma\b \atext\a at the top of the output file.]:[text]
[r:regress?Massage output for regression testing.]
[R:root?alternate root.]:[dir]
[s:shell?Sets the internal shell name to \aname\a. Used for debugging
	Bourne shell compatibility (otherwise \biffe\b uses \aksh\a constructs
	if available). The supported names are \bksh\b, \bbsh\b, \bbash\b, and
	\bosh\b. \bosh\b forces the \bread -r\b compatibility read command to
	be compiled and used instead of \bread -r\b. The default is determined
	by probing the shell at startup.]:[name]
[S:static?Sets the C compiler flags that force static linking. If not set
	then \biffe\b probes the compiler to determine the flags. \biffe\b
	must use static linking (no dlls) because on some systems missing
	library symbols are only detected when referenced at runtime from
	dynamically linked executables.]:[flags]
[u:undef?\b#undef\b failed test macros. By default only successful test macros
	are defined \b1\b.]
[v:verbose?Produce a message line on the standard error for each test as
	it is performed.]
[x:cross?Some tests compile an executable (\ba.out\b) and then run it.
	If the C compiler is a cross compiler and the executable format is
	incompatible with the execution environment then the generated
	executables must be run in a different environment, possibly on
	another host. \acrosstype\a is the HOSTTYPE for generated executables
	(the \bpackage\b(1) command generates a consistent HOSTTYPE namespace).
	Generated executables are run via \bcrossexec\b(1) with \acrosstype\a
	as the first argument. \bcrossexec\b supports remote execution for
	cross-compiled executables. See \bcrossexec\b(1) for
	details.]:[crosstype]
[X:exclude?Removes \b-I\b\adir\a and \b-I\b*/\adir\a C compiler flags.]:[dir]

[ - ] [ file.iffe | statement [ : statement ... ] ]

[+SYNTAX?\biffe\b input consists of a sequence of statement lines. Statements
	that span more than one line contain \abegin\a\b{\b as the last
	operand (where \abegin\a is command specific) and zero
	or more data lines terminated by a line containing
	\b}end\b as the first operand. The statement syntax is:
	[\aname\a \b=\b]] [\b!\b]] \atest\a[,\atest\a...]] [\b-\b]]
	[\aarg\a[,\aarg\a...]]]] [\aprereq\a ...]]
	[\abegin\a{ ... |\bend\b ...]] [= [\adefault\a]]]].
	\atest\as and \aarg\as may be combined, separated by commas, to perform
	a set of tests on a set of arguments. \aname\a \b=\b before \atest\a
	overrides the default test variable and macro name, and \b-\b after
	\atest\a performs the test but does not define the test variable and
	macro values. \b!\b before \atest\a inverts the test sense for \bif\b,
	\belif\b, and \byes{\b and \bno{\b blocks.]
[+?\aprereq\as are used when applying the features tests and may be
	combinations of:]{
		[+compiler options?\b-D\b*, \b-L\b*, etc.]
		[+library references?\b-l\b*, *\b.a\b, etc. \b_LIB_\b\aname\a
			is defined to be 1 if \b-l\b\aname\a is a library.]
		[+header references?*\b.h\b. \a_dir_name\a is defined to be 1
			if \adir/name\a\b.h\b is a header, or if \adir\a is
			omitted, \b_hdr_\b\aname\a is defined to be 1 if
			\aname\a\b.h\b is a header.]
		[+-?Prereq grouping mark; prereqs before the first \b-\b are
			passed to all feature tests. Subsequent groups
			are attempted in left-to-right order until the first
			successful group is found.]
	}
[+?\abegin\a\b{\b ... \b}end\b delimit multiline code blocks that override
	or augment the default code provided by \biffe\b. User supplied code
	blocks should be compatible with the K&R, ANSI, and C++ C language
	dialects for maximal portability. Test code may call the function
	\bNOTE("...")\b to emit short text in \b--verbose\b output; only one
	\bNOTE()\b should be called per test for readability. In addition to
	all macro definitions generated by previous tests, all generated
	code contains the following at the top to hide dialect differences:]{
		[+ ?#if defined(__STDC__) || defined(__cplusplus) || defined(c_plusplus)]
		[+ ?#define _STD_ 1]
		[+ ?#define _ARG_(x) x]
		[+ ?#define _VOID_ void]
		[+ ?#else]
		[+ ?#define _STD_ 0]
		[+ ?#define _ARG_(x) ()]
		[+ ?#define _VOID_ char]
		[+ ?#endif]
		[+ ?#if defined(__cplusplus)]
		[+ ?#define _BEGIN_EXTERNS_ extern "C" {]
		[+ ?#define _END_EXTERNS_ }]
		[+ ?#else]
		[+ ?#define _BEGIN_EXTERNS_]
		[+ ?#define _END_EXTERNS_]
		[+ ?#endif]
		[+ ?#define _NIL_(x) ((x)0)]
		[+ ?#include <stdio.h>]
	}
[+?= \adefault\a may be specified for the \bkey\b, \blib\b, \bmac\b, \bmth\b
	and \btyp\b tests. If the test fails for \aarg\a then
	\b#define\b \aarg\a \adefault\a is emitted. \bkey\b accepts multiple
	\b= \b\adefault\a values; the first valid one is used.]
[+?Each test statement generates a portion of a C language header that contains
	macro defintions, comments, and other text corresponding to the feature
	tests. \b#ifndef _def_\b\aname\a\b_\b\adirectory\a ...
	\b#endif\b guards the generated header from multiple \b#include\bs,
	where \aname\a is determined by either the \brun\b statement input file
	name if any, or the first \atest\a in the first statement, and \adirectory\a
	is the basename component of either the \brun\b statement file, if any,
	or the current working directory. The output file name is determined
	in this order:]{
		[+-?If the first command line operand is \b-\b then the output
			is written to the standard output.]
		[+--output=\afile\a?Output is \afile\a.]
		[+set out \afile\a?Output is \afile\a.]
		[+[run]] [\adirectory\a/]]\abase\a[\a.suffix\a]]?Output is
			\bFEATURE/\b\abase\a.]
	}
[+?Generated \biffe\b headers are often referenced in C source as:
	\b#include "FEATURE/\b\afile\a". The \bnmake\b(1) base rules contain
	metarules for generating \bFEATURE/\b\afile\a from
	\bfeatures/\b\afile\a[\asuffix\a]], where \asuffix\a may be omitted,
	\b.c\b, or \b.sh\b (see the \brun\b test below). Because
	\b#include\b prerequisites are automatically detected, \bnmake\b(1)
	ensures that all prerequisite \biffe\b headers are generated before
	compilation. Note that the directories are deliberately named
	\bFEATURE\b and \bfeatures\b to keep case-ignorant file systems
	happy.]
[+?The feature tests are:]{
	[+# \acomment\a?Comment line - ignored.]
	[+api \aname\a \aYYYYMMDD\a \asymbol ...\a?Emit api compatibility tests
		for \aname\a and \b#define\b \asymbol\a \asymbol\a_\aYYYYMMDD\a
		when \aNAME\a_API is >= \aYYYYMMDD\a (\aNAME\a is \aname\a
		converted to upper case). If \aNAME\a_API is not defined
		then \asymbol\a maps to the newest \aYYYYMMDD\a for \aname\a.]
	[+define \aname\a [ (\aarg,...\a) ]] [ \avalue\a ]]?Emit a macro
		\b#define\b for \aname\a if it is not already defined. The
		definition is passed to subsequent tests.]
	[+extern \aname\a \atype\a [ (\aarg,...\a) | [\adimension\a]] ]]?Emit
		an \bextern\b prototype for \aname\a if one is not already
		defined. The prototype is passed to subsequent tests.]
	[+header \aheader\a?Emit \b#include <\b\aheader\a\b>\b if \aheader\a
		exists. The \b#include\b is passed to subsequent tests.]
	[+print \atext\a?Copy \atext\a to the output file. \atext\a is passed
		to subsequent tests.]
	[+reference \aheader\a?If \aheader\a exists then add \b#include\b
		\aheader\a to subsequent tests.]
	[+ver \aname\a \aYYYYMMDD\a?\b#define\b \aNAME\a_VERSION \aYYYYMMDD\a
		(\aNAME\a is \aname\a converted to upper case).]
	[+cmd \aname\a?Defines \b_cmd_\b\aname\a if \aname\a is an executable
		in one of the standard system directories (\b/bin, /etc,
		/usr/bin, /usr/etc, /usr/ucb\b).
		\b_\b\adirectory\a\b_\b\aname\a is defined for \adirectory\a
		in which \aname\a is found (with \b/\b translated to \b_\b).]
	[+dat \aname\a?Defines \b_dat_\b\aname\a if \aname\a is a data symbol
		in the default libraries.]
	[+def \aname\a?Equivalent to \bcmd,dat,hdr,key,lib,mth,sys,typ\b
		\aname\a.]
	[+dfn \aname\a?If \aname\a is a macro in the candidate headers then
		a \b#define\b \aname\a \avalue\a statment is output for the
		\avalue\a defined in the headers. The definition is \b#ifndef\b
		guarded.]
	[+exp \aname\a \aexpression\a?If \aexpression\a is a \"...\" string
		then \aname\a is defined to be the string, else if the
		\bexpr\b(1) evaluation of \aexpression\a is not 0 then \aname\a
		is defined to be 1, otherwise \aname\a is defined to be 0.
		Identifiers in \aexpression\a may be previously defined names
		from other \biffe\b tests; undefined names evaluate to 0.
		If \aname\a was defined in a previous successful test then
		the current and subsequent \bexp\b test on \aname\a are
		skipped. If \aname\a is \b-\b then the \aexpression\a is
		simply evaluated.]
	[+hdr \aname\a?Defines \b_hdr_\b\aname\a if the header
		\b<\b\aname\a\b.h>\b exists. The \b--config\b macro name is
		\bHAVE_\b\aNAME\a\b_H\b.]
	[+if \astatement\a ... | \belif\b \astatement\a ... | \belse\b | \bendif\b?
		Nested if-else test control.]
	[+iff \aname\a?The generated header \b#ifndef-#endif\b macro guard is
		\b_\b\aname\a\b_H\b.]
	[+inc \afile\a [ re ]]?Read #define macro names from \afile\a
		and arrange for those names to evaluate to 1 in \bexp\b
		expressions. If \are\a is specified then macros not matching
		\are\a are ignored.]
	[+key \aname\a?Defines \b_key_\b\aname\a if \aname\a is a reserved
		word (keyword).]
	[+lcl \aname\a?Generates a \b#include\b statement for the native version
		of the header \b<\b\aname\a\b.h>\b if it exists. Defines
		\b_lcl_\b\aname\a on success. The \b--config\b macro name is
		\bHAVE_\b\aNAME\a\b_H\b. The default \are\a is \b^HAVE_\b
		for \b--config\b and \b^_\b otherwise.]
	[+lib \aname\a?Defines \b_lib_\b\aname\a if \aname\a is an external
		symbol in the default libraries.]
	[+mac \aname\a?Defines \b_mac_\b\aname\a if \aname\a is a macro.]
	[+mem \astruct.member\a?Defines \b_mem_\b\amember\a\b_\b\astruct\a
		if \amember\a is a member of the structure \astruct\a.]
	[+mth \aname\a?Defines \b_mth_\b\aname\a if \aname\a is an external
		symbol in the math library.]
	[+nop \aname\a?If this is the first test then \aname\a may be used
		to name the output file and/or the output header guard macro.
		Otherwise this test is ignored.]
	[+npt \aname\a?Defines \b_npt_\b\aname\a if the \aname\a symbol
		requires a prototype. The \b--config\b macro name is
		\bHAVE_\aNAME\a\b_DECL\b with the opposite sense.]
	[+num \aname\a?Defines \b_num_\b\aname\a if \aname\a is a numeric
		constant \aenum\a or \amacro\a.]
	[+nxt \aname\a?Defines a string macro \b_nxt_\b\aname\a suitable for
		a \b#include\b statement to include the next (on the include
		path) or native version of the header \b<\b\aname\a\b.h>\b
		if it exists. Also defines the \"...\" form
		\b_nxt_\b\aname\a\b_str\b. The \b--config\b macro name is
		\bHAVE_\b\aNAME\a\b_NEXT\b.]
	[+one \aheader\a ...?Generates a \b#include\b statement for the first
		header found in the \aheader\a list.]
	[+opt \aname\a?Defines \b_opt_\b\aname\a if \aname\a is a space-separated
		token in the global environment variable \bPACKAGE_OPTIONS\b.]
	[+pth \afile\a [ \adir\a ... | { \ag1\a - ... - \agn\a } | < \apkg\a [\aver\a ...]] > ]]?Defines
		\b_pth_\b\afile\a, with embedded \b/\b chars translated to
		\b_\b, to the path of the first instance of \afile\a in the
		\adir\a directories. \b{\b ... \b}\b forms a directory list
		from the cross-product of \b-\b separated directory groups
		\ag1\a ... \agn\a. < ... > forms a directory list for the
		package \apkg\a with optional versions. If no operands are
		specified then the default PATH directories are used. The
		\b--config\b macro name is \aNAME\a\b_PATH\b.]
	[+run \afile\a?Runs the tests in \afile\a based on the \afile\a
		suffix:]{
		[+.c?\afile\a is compiled and executed and the output is copied
			to the \biffe\b output file. Macros and headers supplied
			to \bbegin{\b ... \b}end\b are also supplied to
			\afile\a.]
		[+.sh?\afile\a is executed as a shell script and the output is
			copied to the \biffe\b output file.]
		[+.iffe \bor no suffix?\afile\a contains \biffe\b
			statements.]
	}
	[+set \aoption value\a?Sets option values. The options are described
		above.]
	[+siz \aname\a?Defines \b_siz_\b\aname\a to be \bsizeof\b(\aname\a) if
		\aname\a is a type in any of \b<sys/types.h>, <times.h>,
		<stddef.h>, <stdlib.h>\b. Any \b.\b characters in \aname\a are
		translated to space before testing and are translated to \b_\b
		in the output macro name.]
	[+sym \aname\a?Defines \b_ary_\b\aname\a if \aname\a is an array,
		\b_fun_\b\aname\a if \aname\a is a function pointer,
		\b_ptr_\b\aname\a if \aname\a is a pointer, or
		\b_reg_\b\aname\a if \aname\a is a scalar. In most cases
		\aname\a is part of a macro expansion.]
	[+sys \aname\a?Defines \b_sys_\b\aname\a if the header
		\b<sys/\b\aname\a\b.h>\b exists. The \b--config\b macro name is
		\bHAVE_SYS_\b\aNAME\a\b_H\b.]
	[+tst \aname\a?A user defined test on name. A source block must be
		supplied. Defines \b_\b\aname\a on success. \btst - ...\b is
		treated as \btst - - ...\b.]
	[+typ \aname\a?Defines \b_typ_\b\aname\a if \aname\a is a type in any
		of \b<sys/types.h>, <times.h>, <stddef.h>, <stdlib.h>\b. Any
		\b.\b characters in \aname\a are translated to space before
		testing and are translated to \b_\b in the output macro name.]
	[+val \aname\a?The output of \becho\b \aname\a is written to the
		output file.]
	[+var \aname\a?A user defined test on name. A source block must be
		supplied. Sets the \bexp\b variable \b_\b\aname\a on success
		but does not define a macro.]
	[+(\aexpression\a)?Equivalent to \bexp -\b \aexpression\a.]
}
[+?Code block names may be prefixed by \bno\b to invert the test sense. The
	block names are:]{
	[+cat?The block is copied to the output file.]
	[+compile?The block is compiled (\bcc -c\b).]
	[+cross?The block is executed as a shell script using \bcrossexec\b(1)
		if \b--cross\b is on, or on the local host otherwise, and the
		output is copied to the output file. Test macros are not
		exported to the script.]
	[+execute?The block is compiled, linked, and executed. \b0\b exit
		status means success.]
	[+fail?If the test fails then the block text is evaluated by
		\bsh\b(1).]
	[+link?The block is compiled and linked (\bcc -o\b).]
	[+macro?The block is preprocessed (\bcc -E\b) and lines containing
		text bracketed by \b<<"\b ... \b">>\b (\aless-than less-than
		double-quote ... double-quote greater-than greater-than\a)
		are copied to the output file with the brackets omitted.]
	[+no?If the test fails then the block text is copied to the
		output file. Deprecated: use { \bif\b \belif\b \belse\b
		\bendif\b } with unnamed \b{\b ... \b}\b blocks.]
	[+note?If the test succeeds then the block is copied to the output
		as a \b/*\b ... \b*/\b comment.]
	[+output?The block is compiled, linked, and executed, and the output
		is copied to the output file.]
	[+pass?If the test succeeds then the block text is evaluated by
		\bsh\b(1).]
	[+preprocess?The block is preprocessed (\bcc -E\b).]
	[+run?The block is executed as a shell script and the output is
		copied to the output file. Succesful test macros are also
		defined as shell variables with value \b1\b and are available
		within the block. Likewise, failed test macros are defined
		as shell variables with value \b0\b.]
	[+status?The block is compiled, linked, and executed, and the exit
		status is the test outcome, 0 for \afailure\a, the value
		otherwise.]
	[+yes?If the test succeeds then the block text is copied to the output
		file. \byes{\b ... \b}end\b is equivalent to the unnamed block
		\b{\b ... \b}\b.  Deprecated: use { \bif\b \belif\b \belse\b
		\bendif\b } with unnamed \b{\b ... \b}\b blocks.]
}
[+SEE ALSO?\bautoconf\b(1), \bconfig\b(1), \bgetconf\b(1), \bcrossexec\b(1),
	\bnmake\b(1), \bpackage\b(1), \bproto\b(1), \bsh\b(1)]
'
	while	getopts -a "$command" "$USAGE" OPT
	do	case $OPT in
		a)	set="$set set all :" ;;
		c)	set="$set set cc $OPTARG :" ;;
		C)	set="$set set config :" ;;
		d)	set="$set set debug $OPTARG :" ;;
		D)	set="$set set define :" ;;
		E)	set="$set set explicit :" ;;
		F)	set="$set set features $OPTARG :" ;;
		i)	set="$set set input $OPTARG :" ;;
		I)	set="$set set include $OPTARG :" ;;
		L)	set="$set set library $OPTARG :" ;;
		n)	set="$set set namval $OPTARG :" ;;
		N)	set="$set set nooptimize $OPTARG :" ;;
		o)	set="$set set output $OPTARG :" ;;
		e)	set="$set set package $OPTARG :" ;;
		p)	set="$set set prototyped :" ;;
		P)	set="$set set pragma $OPTARG :" ;;
		r)	set="$set set regress :" ;;
		R)	set="$set set altroot $OPTARG :" ;;
		s)	set="$set set shell $OPTARG :" ;;
		S)	set="$set set static $OPTARG :" ;;
		O)	set="$set set stdio $OPTARG :" ;;
		u)	set="$set set undef :" ;;
		v)	set="$set set verbose :" ;;
		x)	set="$set set cross $OPTARG :" ;;
		X)	set="$set set exclude $OPTARG :" ;;
		esac
	done
	shift `expr $OPTIND - 1`
	;;
*)	while	:
	do	case $# in
		0)	break ;;
		esac
		case $1 in
		-)	break
			;;
		--)	shift
			break
			;;
		--a|--al|--all)
			REM=a
			;;
		--cc=*)	REM=c`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--co|--con|--conf|--confi|--config)
			REM=C
			;;
		--cr=*|--cro=*|--cros=*|--cross=*)
			REM=x`echo X$1 | sed -e 's,[^=]*=,,'`
			;;
		--d=*|--de=*|--deb=*|--debu=*|--debug=*)
			REM=d`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--def|--defi|--defin|--define)
			REM=D
			;;
		--e=*|--ex=*|--exc=*|--excl=*|--exclu=*|--exclud=*|--exclude=*)
			REM=X`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--e|--ex|--exp|--expl|--expli|--explic|--explici|--explicit)
			REM=E
			;;
		--f=*|--fe=*|--fea=*|--feat=*|--featu=*|--featur=*|--feature=*|--features=*)
			REM=F`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--inp=*|--inpu=*|--input=*)
			REM=i`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--inc=*|--incl=*|--inclu=*|--includ=*|--include=*)
			REM=I`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--l=*|--li=*|--lib=*|--libr=*|--libra=*|--librar=*|--library=*)
			REM=L`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--n|--na|--nam|--name|--name-v|--name-va|--name-val|--name-valu|--name-value)
			REM=n
			;;
		--o=*|--ou=*|--out=*|--outp=*|--outpu=*|--output=*)
			REM=o`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--pa=*|--pac=*|--pack=*|--packa=*|--packag=*|--package=*)
			REM=e`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--pro|--prot|--proto|--protot|--prototy|--prototyp|--prototype|--prototyped)
			REM=p
			;;
		--pra=*|--prag=*|--pragma=*)
			REM=P`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--r|--re|--reg|--regre|--regres|--regress)
			REM=r
			;;
		--sh=*|--she=*|--shel=*|--shell=*)
			REM=s`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--sta=*|--stat=*|--stati=*|--static=*)
			REM=S`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--std=*|--stdi=*|--stdio=*)
			REM=O`echo X$1 | sed 's,[^=]*=,,'`
			;;
		--u|--un|--und|--unde|--undef)
			REM=u
			;;
		--v|--ve|--ver|--verb|--verbo|--verbos|--verbose)
			REM=v
			;;
		--*)	echo $command: $1: unknown option >&2
			exit 2
			;;
		-*)	REM=`echo X$1 | sed 's,X-,,'`
			;;
		*)	break
			;;
		esac
		shift
		while	:
		do	case $REM in
			'')	break ;;
			esac
			eval `echo $REM | sed "s,\(.\)\(.*\),OPT='\1' REM='\2',"`
			case $OPT in
			[cdFiILoOePsSxX])
				case $REM in
				'')	case $# in
					0)	echo $command: -$OPT: option argument expected >&2
						exit 1
						;;
					esac
					OPTARG=$1
					shift
					;;
				*)	OPTARG=$REM
					REM=''
					;;
				esac
			esac
			case $OPT in
			a)	set="$set set all :" ;;
			c)	set="$set set cc $OPTARG :" ;;
			C)	set="$set set config :" ;;
			d)	set="$set set debug $OPTARG :" ;;
			D)	set="$set set define :" ;;
			E)	set="$set set explicit :" ;;
			F)	set="$set set features $OPTARG :" ;;
			i)	set="$set set input $OPTARG :" ;;
			I)	set="$set set include $OPTARG :" ;;
			L)	set="$set set library $OPTARG :" ;;
			n)	set="$set set namval $OPTARG :" ;;
			N)	set="$set set nooptimize $OPTARG :" ;;
			o)	set="$set set output $OPTARG :" ;;
			e)	set="$set set package $OPTARG :" ;;
			p)	set="$set set prototyped :" ;;
			P)	set="$set set pragma $OPTARG :" ;;
			r)	set="$set set regress :" ;;
			s)	set="$set set shell $OPTARG :" ;;
			S)	set="$set set static $OPTARG :" ;;
			O)	set="$set set stdio $OPTARG :" ;;
			u)	set="$set set undef :" ;;
			v)	set="$set set verbose :" ;;
			x)	set="$set set cross $OPTARG :" ;;
			X)	set="$set set exclude $OPTARG :" ;;
			*)	echo "Usage: $command [-aCDEnpruv] [-c C-compiler-name [C-compiler-flags ...]] [-d level]
	    [-F features-header] [-i file] [-o file] [-O stdio-header] [-e name] [-P text]
	    [-s shell-path] [-S[flags]] [-x cross-exec-prefix] [-I dir] [-L dir] [-X dir] [ - ]
	    [ file.iffe | statement [ : statement ... ] ]" >&2
				exit 2
				;;
			esac
		done
	done
	;;
esac
case $1 in
-)	out=-; shift ;;
esac
case $# in
0)	in=- ;;
esac
set -- $set "$@"
case " $* " in
*' set config '*|*' run config.'*|*' run '*' config.'*|*' run '*'/config.'*)
	config=1
	;;
esac

# standard error to /dev/null unless debugging
# standard output to the current output file
#
#	stdout	original standard output
#	stderr	original standard error
#	nullin	/dev/null input
#	nullout	/dev/null output

stdout=5 stderr=6 nullin=7 nullout=8
eval "exec $nullin</dev/null $nullout>/dev/null $stdout>&1 $stderr>&2"
case " $* " in
*" set debug "[3456789]*)
	;;
*)	eval "exec 2>&$nullout"
	;;
esac

# prompt complications

case `print -n aha </dev/null 2>/dev/null` in
aha)	show='print -n' SHOW='' ;;
*)	case `echo -n aha 2>/dev/null` in
	-n*)	show=echo SHOW='\c' ;;
	*)	show='echo -n' SHOW='' ;;
	esac
	;;
esac

# tmp files cleaned up on exit
# status: 0:success 1:failure 2:interrupt

status=1
case $debug in
2)	core=
	;;
*)	if	(ulimit -c 0) >/dev/null 2>&1
	then	ulimit -c 0
		core=
	else	core="core core.??*"
	fi
	;;
esac
trap "rm -f $core $tmp*" 0
if	(:>$tmp.c) 2>/dev/null
then	rm -f $tmp.c
else	echo "$command: cannot create tmp files in current dir" >&2
	exit 1
fi
status=2

# standard header for c source

std='#if defined(__STDC__) || defined(__cplusplus) || defined(c_plusplus)
#define _STD_		1
#define _ARG_(x)	x
#define _VOID_		void
#else
#define _STD_		0
#define _ARG_(x)	()
#define _VOID_		char
#endif
#if defined(__cplusplus)
#define _BEGIN_EXTERNS_	extern "C" {
#define _END_EXTERNS_	}
#else
#define _BEGIN_EXTERNS_
#define _END_EXTERNS_
#endif
#define _NIL_(x)	((x)0)'
tst=
ext="#include <stdio.h>"
noext='*[<"][Ss][Tt][Dd][Ii][Oo].[Hh][">]*|*<ast.h>*|*<sfio.h>*|*/[*]<NOSTDIO>[*]/*'

# loop on op [ arg [ ... ] ] [ : op [ arg [ ... ] ] ]

argx=0
cur=.
can=
cansep=
cctest=
file=
hdrtest=
ifelse=NONE
ifstack=
ini=
init=1
line=0
nan=
prototyped=
while	:
do	case $in in
	"")	case $argx:$* in
		1:$argv);;
		1:*)	argx=0
			set x $argv
			shift
			;;
		esac
		;;
	*)	case $ini in
		'')	if	read lin
			then	case $shell in
				ksh)	let line=line+1 ;;
				*)	line=`expr $line + 1` ;;
				esac
				$posix_noglob
				set x $lin
				$posix_glob
				case $# in
				1)	continue ;;
				esac
			else	set x
			fi
			;;
		*)	$posix_noglob
			set x $ini
			$posix_glob
			ini=
			;;
		esac
		shift
		case $init in
		1)	case $1 in
			iff)	init=0
				;;
			print|ref|set)
				;;
			*)	init=0
				ini=$*
				set ini
				;;
			esac
		esac
		;;
	esac
	case $# in
	0)	case $ifstack in
		?*)	echo "$command: $file$line: missing endif" >&$stderr
			exit 1
			;;
		esac
		set set out +
		;;
	esac

	# if nesting

	while	:
	do	case $1 in
		"if")	ifstack="$ifelse:$ifstack"
			case $ifelse in
			KEEP|NONE)
				ifelse=TEST
				;;
			TEST)	;;
			*)	ifelse=DONE
				;;
			esac
			shift
			case $explicit in
			1)	set '' - "$@"; shift ;;
			esac
			;;
		"elif")	case $ifelse in
			SKIP)	ifelse=TEST
				;;
			TEST)	;;
			*)	ifelse=DONE
				;;
			NONE)	echo "$command: $file$line: $1: no matching if" >&$stderr
				exit 1
				;;
			esac
			shift
			case $explicit in
			1)	set '' - "$@"; shift ;;
			esac
			;;
		"else")	case $ifelse in
			KEEP)	ifelse=DONE
				;;
			SKIP|TEST)
				ifelse=KEEP
				;;
			NONE)	echo "$command: $file$line: $1: no matching if" >&$stderr
				exit 1
				;;
			esac
			shift
			;;
		"endif")case $ifelse in
			NONE)	echo "$command: $file$line: $1: no matching if" >&$stderr
				exit 1
				;;
			esac
			case $shell in
			ksh)	ifelse=${ifstack%%:*}
				ifstack=${ifstack#*:}
				;;
			*)	eval `echo $ifstack | sed 's,\([^:]*\):\(.*\),ifelse=\1 ifstack=\2,'`
				;;
			esac
			shift
			;;
		*)	break
			;;
		esac
	done

	# check if "run xxx" is equivalent to "set in xxx"

	case $1 in
	"("*)		set exp - "$@" ;;
	*.iffe|*.iff)	set run "$@" ;;
	esac
	case $1 in
	:)	shift
		continue
		;;
	run)	case $shell in
		bsh)	case $2 in
			*/*)	x=`echo $2 | sed 's,.*[\\\\/],,'` ;;
			*)	x=$2 ;;
			esac
			;;
		*)	eval 'x=${2##*[\\/]}'
			;;
		esac
		case $x in
		*.iffe|*.iff)
			set set in $2 ;;
		*.*)	;;
		*)	set set in $2 ;;
		esac
		;;
	esac

	# { inc set } drop out early

	case $1 in
	""|"#"*)continue
		;;
	inc)	case $ifelse in
		DONE|SKIP)	set ''; shift; continue ;;
		esac
		shift
		case $# in
		0)	echo "$command: $file$line: path expected" >&$stderr
			exit 1
			;;
		esac
		p=$1
		shift
		if	test ! -f $p
		then	echo "$command: $file$line: $p: file not found" >&$stderr
			exit 1
		fi
		case $# in
		0)	case $config in
			1)	e="^HAVE_" ;;
			*)	e="^_" ;;
			esac
			;;
		1)	e=$1
			;;
		*)	shift
			echo "$command: $file$line: warning: $*: operands ignored" >&$stderr
			;;
		esac
		eval `sed -e '/^#define[ 	]/!d' -e 's/#define[ 	]//' -e 's/[ 	(].*//' ${e:+"-e/$e/!d"} -e 's/.*/&=1/' $p | LC_ALL=C sort -u`
		continue
		;;
	set)	case $ifelse in
		DONE|SKIP)	set ''; shift; continue ;;
		esac
		shift
		case $1 in
		""|"#"*)op=
			;;
		*)	arg=
			op=$1
			case $op in
			--*)	case $shell in
				bsh)	op=`echo X$op | sed 's/X--//'` ;;
				*)	op=${op#--} ;;
				esac
				;;
			-*)	case $op in
				-??*)	case $shell in
					bsh)	arg=`echo X$op | sed 's/X-.//'`
						op=`echo X$op | sed 's/X\\(-.\\).*/\\1/'`
						;;
					*)	arg=${op#-?}
						op=${op%$arg}
						;;
					esac
					;;
				esac
				case $op in
				a)	op=all ;;
				c)	op=cc ;;
				C)	op=config ;;
				d)	op=debug ;;
				D)	op=define ;;
				E)	op=explicit ;;
				F)	op=features ;;
				i)	op=input ;;
				I)	op=include ;;
				L)	op=library ;;
				n)	op=namval ;;
				N)	op=nooptimize ;;
				o)	op=output ;;
				e)	op=package ;;
				p)	op=prototyped ;;
				P)	op=pragma ;;
				r)	op=regress ;;
				s)	op=shell ;;
				S)	op=static ;;
				O)	op=stdio ;;
				u)	op=undef ;;
				v)	op=verbose ;;
				x)	op=cross ;;
				X)	op=exclude ;;
				esac
				;;
			esac
			shift
			while	:
			do	case $# in
				0)	break ;;
				esac
				case $1 in
				*" "*)	shift
					continue
					;;
				""|"#"*)break
					;;
				:)	shift
					break
					;;
				esac
				case $arg in
				"")	arg=$1 ;;
				*)	arg="$arg $1" ;;
				esac
				shift
			done
			;;
		esac
		case $op in
		all)	all=1
			continue
			;;
		altroot) case $arg in
			""|-)	altroot= ;;
			*)	altroot="$arg" ;;
			esac
			continue
			;;
		cc)	occ=
			for x in $arg
			do	case $occ in
				"")	case $x in
					*=*)	case $shell in
						bsh)	eval $x
							export `echo $x | sed 's/=.*//'`
							;;
						*)	export $x
							;;
						esac
						;;
					-O*)	case $optimize in
						1)	occ=$x ;;
						esac
						;;
					*)	occ=$x
						;;
					esac
					;;
				*)	occ="$occ $x"
					;;
				esac
			done
			exclude occ
			continue
			;;
		config)	config=1
			continue
			;;
		cross)	case $arg in
			""|-)	cross= ;;
			*)	cross="$arg" libpaths= ;;
			esac
			continue
			;;
		debug)	debug=$arg
			case $arg in
			0)	exec 2>&$nullout
				set -
				show=echo
				SHOW=
				;;
			""|1)	exec 2>&$stderr
				set -
				show=echo
				SHOW=
				;;
			2|3)	exec 2>&$stderr
				case $shell in
				ksh)	eval 'PS4="${PS4%+*([ 	])}+\$LINENO+ "'
				esac
				show=echo
				SHOW=
				set -x
				;;
			*)	echo "$command: $arg: debug levels are 0, 1, 2, 3" >&$stderr
				;;
			esac
			continue
			;;
		define)	define=1
			continue
			;;
		exclude)case $arg in
			""|-)	excludes= ;;
			*)	excludes="$excludes $arg" ;;
			esac
			exclude includes occ
			continue
			;;
		explicit)
			explicit=1
			continue
			;;
		features)case $arg in
			'')	tst= ;;
			*)	tst="#include \"$arg\"" ;;
			esac
			continue
			;;
		"in"|input)
			case $arg in
			"")	in=-
				;;
			*)	in=$arg
				if	test ! -r $in
				then	echo "$command: $in: not found" >&$stderr
					exit 1
				fi
				exec < $in
				file=$in:
				case $out in
				"")	case $in in
					*[.\\/]*)
						case $shell in
						bsh)	eval `echo $in | sed -e 's,.*[\\\\/],,' -e 's/\\.[^.]*//' -e 's/^/out=/'`
							;;
						*)	eval 'out=${in##*[\\/]}'
							eval 'out=${out%.*}'
							;;
						esac
						;;
					*)	out=$in
						;;
					esac
					;;
				esac
				;;
			esac
			continue
			;;
		include)case $arg in
			""|-)	includes= ;;
			*)	includes="$includes -I$arg" ;;
			esac
			exclude includes
			continue
			;;
		library)for y in $libpaths
			do	eval $y=\"\$$y:\$arg\$${y}_default\"
				eval export $y
			done
			continue
			;;
		namval)	define=n
			continue
			;;
		nodebug)exec 2>&$nullout
			set -
			continue
			;;
		nodefine)
			define=0
			continue
			;;
		nooptimize)
			optimize=0
			case $occ in
			*" -O"*)occ=`echo $occ | sed 's/ -O[^ ]*//g'`
				cc=$occ
				;;
			esac
			;;
		optimize)
			optimize=1
			;;
		out|output)
			out=$arg
			defhdr=
			usr=
			deflib=
			one=
			puthdr=
			putlib=
			case $op in
			output)	continue ;;
			esac
			def=
			test=
			;;
		package)protoflags="$protoflags -e $arg"
			continue
			;;
		prototyped|noprototyped)
			pragma="$pragma $op"
			case $op in
			prototyped)	prototyped=1 ;;
			*)		prototyped= ;;
			esac
			continue
			;;
		pragma) pragma="$pragma $arg"
			continue
			;;
		regress)regress=1
			version=1995-03-19
			continue
			;;
		shell)	case $arg in
			osh)	posix_read=-no
				shell=bsh
				;;
			esac
			shell=$arg
			continue
			;;
		static)	static=$arg
			continue
			;;
		stdio)	case $arg in
			'')	ext=
				;;
			*)	ext=
				sep=
				for i in $arg
				do	case $i in
					-)	case $ext in
						'')	continue ;;
						*)	break ;;
						esac
						;;
					esac
					echo "#include \"$i\"" > t.c
					if	$cc -E t.c > /dev/null 2>&1
					then	ext="$ext$sep#include \"$arg\""
						sep=$nl
					fi
				done
				;;
			esac
			continue
			;;
		undef)	undef=1
			continue
			;;
		verbose)verbose=1
			continue
			;;
		*)	echo "$command: $op: unknown option" >&$stderr
			exit 1
			;;
		esac
		;;
	api|define|extern|header|include|print|reference|ver)
		op=$1
		shift
		arg=
		;;
	*)	case $2 in
		'=')	def=$1
			shift
			shift
			;;
		*)	case $1 in
			'-'|'?')def=-
				shift
				;;
			*)	def=
				;;
			esac
			;;
		esac
		case $1 in
		'!')	not=1
			shift
			;;
		*)	not=
			;;
		esac
		case $1 in
		*'{')	op=-
			;;
		'('*|'"'*'"'|'<'*'>')
			op=exp
			case $def in
			'')	def=- ;;
			esac
			;;
		*)	op=$1
			shift
			;;
		esac
		arg=
		cc="$occ $includes"
		group=
		groups=
		fail=
		hdr=
		lib=
		mac=
		no=
		note=
		opt=
		pass=
		pth=
		run=
		set=
		src=
		test=
		yes=
		case $# in
		0)	;;
		*)	case $1 in
			"#"*)	set x
				shift
				;;
			*)	case $op in
				ref)	;;
				*)	case $1 in
					'-')	case $op:$2 in
						tst:*)	arg=$1
							case $2 in
							-)	shift ;;
							esac
							;;
						*:-*)	arg=$1
							shift
							;;
						*)	def=-
							shift
							case $1 in
							'('*|*'{'|'"'*'"'|'<'*'>')
								arg=-
								;;
							*)	arg=$1
								case $# in
								0)	;;
								*)	shift ;;
								esac
								;;
							esac
							;;
						esac
						;;
					-*|+*|'('*|*'{'|'"'*'"'|'<'*'>')
						arg=-
						;;
					*)	arg=$1
						shift
						;;
					esac
					;;
				esac
				;;
			esac
			case $1 in
			'('*|'"'*'"'|'<'*'>')
				while	:
				do	case $# in
					0)	break ;;
					esac
					case $1 in
					*[.{}]*)break ;;
					esac
					case $test in
					'')	test=$1 ;;
					*)	test="$test $1" ;;
					esac
					shift
				done
				case $arg in
				'')	arg=- ;;
				esac
				case $op in
				exp)	case $def in
					''|'-')	;;
					*)	arg=$def ;;
					esac
					;;
				esac
				;;
			esac
			sline=$line
			while	:
			do	case $# in
				0)	break ;;
				esac
				case $1 in
				"")	;;
				"#"*)	set x
					;;
				"=")	shift
					set=$*
					case $set in
					"")	set=" " ;;
					esac
					while	:
					do	case $# in
						0)	break ;;
						esac
						shift
					done
					break
					;;
				[abcdefghijklmnopqrstuvwxyz]*'{'|'{')
					v=$1
					shift
					x=
					case $v in
					"note{")
						sep=" " ;;
					*)	sep=$nl ;;
					esac
					case $v in
					'{')	e='}' ;;
					*)	e='}end' ;;
					esac
					n=1
					SEP=
					while	:
					do	case $# in
						0)	case $posix_read in
							-*)	checkread ;;
							esac
							case $in in
							"")	echo "$command: $file$line: missing }end" >&$stderr
								exit 1
								;;
							esac
							while	:
							do	case $posix_read in
								1)	case $shell in
									ksh)	IFS= read -r lin
										eof=$?
										while	:
										do	lin="${lin#[' 	']}"
											case $lin in
											[' 	']*'#'*);;
											*)		break ;;
											esac
										done
										;;
									*)	IFS=
										read -r lin
										eof=$?
										IFS=$ifs
										case $lin in
										[' 	']*) lin=`sed -e 's,^[ 	],,' -e 's,^[ 	]*#,#,' <<!
$lin
!
`
											;;
										esac
										;;
									esac
									;;
								*)	lin=`$posix_read`
									eof=$?
									;;
								esac
								case $eof in
								0)	case $shell in
									ksh)	let line=line+1 ;;
									*)	line=`expr $line + 1` ;;
									esac
									$posix_noglob
									set x $lin
									$posix_glob
									case $2 in
									$v)	case $shell in
										ksh)	let n=n+1 ;;
										*)	n=`expr $n + 1` ;;
										esac
										;;
									$e|$e';')
										case $n in
										1)	shift
											break 2
											;;
										esac
										case $shell in
										ksh)	let n=n-1 ;;
										*)	n=`expr $n - 1` ;;
										esac
										;;
									esac
									x="$x$SEP$lin"
									SEP=$sep
									;;
								*)	echo "$command: $file$line: missing $e" >&$stderr
									exit 1
									;;
								esac
							done
							;;
						esac
						case $1 in
						$v)	case $shell in
							ksh)	let n=n+1 ;;
							*)	n=`expr $n + 1` ;;
							esac
							;;
						$e|$e';')
							case $n in
							1)	break ;;
							esac
							case $shell in
							ksh)	let n=n-1 ;;
							*)	n=`expr $n - 1` ;;
							esac
							;;
						esac
						x="$x$SEP$1"
						SEP=$sep
						shift
					done
					case $v in
					'note{');;
					*)	x="$x$nl" # \r\n bash needs this barf # ;;
					esac
					case $v in
					'fail{')	fail=$x ;;
					'nofail{')	pass=$x v='pass{' ;;
					'nopass{')	fail=$x v='fail{' ;;
					'no{')		no=$x ;;
					'note{')	note=$x ;;
					'pass{')	pass=$x ;;
					'test{')	test=$x ;;
					'yes{'|'{')	yes=$x ;;
					*)		src=$x run=$v ;;
					esac
					;;
				:)	shift
					break
					;;
				*[\"\'\(\)\{\}\ \	]*)
					case $op in
					pth)	pth="$pth $1"
						;;
					*)	case $test in
						'')	test=$1 ;;
						*)	test="$test $1" ;;
						esac
						;;
					esac
					;;
				-)	group=$group$1
					case $group in
					-)	com_hdr=$hdr
						com_lib=$lib
						com_mac=$mac
						com_opt=$opt
						com_pth=$pth
						com_test=$test
						;;
					*)	groups="$groups $1"
						;;
					esac
					;;
				-l*)	case $group in
					--*)	groups="$groups $1" ;;
					*)	lib="$lib $1" ;;
					esac
					;;
				+l*)	case $shell in
					bsh)	x=`echo X$1 | sed 's/X+/-/'` ;;
					*)	eval 'x=-${1#+}' ;;
					esac
					case $group in
					--*)	groups="$groups $x" ;;
					*)	lib="$lib $x" ;;
					esac
					;;
				-*|+*)	case $op in
					ref)	cc="$cc $1"
						occ="$occ $1"
						case $1 in
						-L*)	case $shell in
							ksh)	x=${1#-L} ;;
							*)	x=`echo x$1 | sed 's,^x-L,,'` ;;
							esac
							for y in $libpaths
							do	eval $y=\"\$$y:\$x\$${y}_default\"
								eval export $y
							done
							;;
						esac
						;;
					*)	case $group in
						--*)	groups="$groups $1"
							;;
						*)	case $op in
							run)	opt="$opt $1"
								;;
							*)	case $1 in
								-D*)	mac="$mac $1" ;;
								*)	cc="$cc $1" ;;
								esac
								;;
							esac
							;;
						esac
						;;
					esac
					;;
				*.[aAxX]|*.[dD][lL][lL]|*.[lL][iI][bB])
					case $group in
					--*)	groups="$groups $1" ;;
					*)	lib="$lib $1" ;;
					esac
					;;
				*[.\\/]*)
					case $group in
					--*)	groups="$groups $1"
						;;
					*)	case $op in
						pth)	pth="$pth $1" ;;
						*)	hdr="$hdr $1" ;;
						esac
						;;
					esac
					;;
				*)	case $group in
					--*)	groups="$groups $1"
						;;
					*)	case $op in
						pth)	pth="$pth $1"
							;;
						*)	case $test in
							'')	test=$1 ;;
							*)	test="$test $1" ;;
							esac
							;;
						esac
						;;
					esac
					;;
				esac
				shift
			done
			case $group in
			-)	group= ;;
			esac
			;;
		esac
		;;
	esac
	case $ifelse in
	DONE|SKIP)	continue ;;
	esac

	# make sure $cc compiles C

	case $cc in
	"")	cc="$occ $includes" ;;
	esac
	case $cctest in
	"")	checkcc ;;
	esac

	# some ops allow no args

	case $arg in
	'')	case $op in
		api)	arg=-
			case $1:$2 in
			[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]*:[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])
				a=$1
				shift
				case " $apis " in
				*" $a "*)
					;;
				*)	apis="$apis $a"
					eval api_sym_${a}= api_ver_${a}=
					;;
				esac
				rel=
				while	:
				do	case $# in
					0)	break ;;
					esac
					case $1 in
					[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])
						rel="$rel $1"
						;;
					*)	break
						;;
					esac
					shift
				done
				while	:
				do	case $# in
					0)	break ;;
					esac
					case $1 in
					:)	break ;;
					esac
					eval syms='$'api_sym_${a}
					case $syms in
					'')	sep='' ;;
					*)	sep=$nl ;;
					esac
					for r in $rel
					do	syms=$syms$sep${1}:${r}
						sep=$nl
					done
					eval api_sym_${a}='$'syms
					shift
				done
				;;
			*)	echo "$command: $op: expected: name YYYYMMDD symbol ..." >&$stderr
				;;
			esac
			while	:
			do	case $# in
				0)	break ;;
				esac
				case $1 in
				:)	break ;;
				esac
				shift
			done
			;;
		iff|ini)arg=-
			;;
		comment)copy - "/* $* */"
			continue
			;;
		define)	x=$1
			shift
			case $1 in
			'('*')')
				arg=$1
				shift
				;;
			esac
			case $in in
			"")	v=
				while	:
				do	case $# in
					0)	break ;;
					esac
					t=$1
					shift
					case $t in
					":")	break ;;
					esac
					v="$v $t"
				done
				;;
			*)	v=$*
				;;
			esac
			is mac $x
			copy $tmp.c "$std
$usr
#ifndef $x
(
#endif
int x;
"
			if	compile $cc -c $tmp.c <&$nullin >&$nullout
			then	success -
			else	failure -
				copy - "#define $x$arg	$v"
				usr="$usr${nl}#define $x$arg  $v"
			fi
			continue
			;;
		extern)	x=$1
			shift
			t=$1
			shift
			is npt $x
			copy $tmp.c "
$std
#include <sys/types.h>
$usr
_BEGIN_EXTERNS_
struct _iffe_struct { int _iffe_member; };
extern struct _iffe_struct* $x _ARG_((struct _iffe_struct*));
_END_EXTERNS_
"
			# some compilers with -O only warn for invalid intrinsic prototypes
			case " $cc " in
			*" -O "*)	xx=`echo $cc | sed 's/ -O / /g'` ;;
			*)		xx=$cc ;;
			esac
			if	compile $xx -c $tmp.c <&$nullin >&$nullout
			then	success -
				while	:
				do	case $1 in
					''|'('*|'['*)
						break
						;;
					esac
					t="$t $1"
					shift
				done
				case $in in
				"")	v=
					while	:
					do	case $# in
						0)	break ;;
						esac
						t=$1
						shift
						case $t in
						":")	break ;;
						esac
						v="$v $t"
					done
					;;
				*)	v=$*
					;;
				esac
				copy - "extern $t	$x$v;"
				# NOTE: technically if prototyped is on all tests should
				#	be run through proto(1), but we'd like iffe to
				#	work sans proto -- so we drop the extern's in
				#	the test headers
				case $prototyped in
				'')	usr="$usr${nl}extern $t $x$v;" ;;
				esac
			else	failure -
				case $in in
				"")	while	:
					do	case $# in
						0)	break ;;
						esac
						case $1 in
						":")	break ;;
						esac
					done
					;;
				esac
			fi
			continue
			;;
		header|include|reference)
			while	:
			do	case $# in
				0)	break ;;
				esac
				x=$1
				shift
				case $x in
				":")	break ;;
				esac
				case " $gothdr " in
				*" - $x "*)
					;;
				*" + $x "*)
					case $usr in
					*"# include <"$x">"*)
						;;
					*)	case $op in
						reference)
							;;
						*)	copy - "#include <$x>"
							;;
						esac
						usr="$usr${nl}#include <$x>"
						;;
					esac
					;;
				*)	copy $tmp.c "$std
$usr
#include <$x>
int x;
"
					if	is_hdr - $x
					then	gothdr="$gothdr + $x"
						case $op in
						reference)
							;;
						*)	copy - "#include <$x>"
							;;
						esac
						usr="$usr${nl}#include <$x>"
					else	gothdr="$gothdr - $x"
					fi
					;;
				esac
			done
			continue
			;;
		print)	case $in in
			"")	v=
				while	:
				do	case $# in
					0)	break ;;
					esac
					t=$1
					shift
					case $t in
					":")	break ;;
					esac
					v="$v $t"
				done
				;;
			*)	v=$*
				;;
			esac
			copy - "$*"
			usr="$usr${nl}$v"
			continue
			;;
		ver)	arg=-
			case $1:$2 in
			[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]*:[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])
				vers="$vers$nl$1"
				eval ver_$1=$2
				;;
			*)	echo "$command: $op: expected: name YYYYMMDD" >&$stderr
				;;
			esac
			while	:
			do	case $# in
				0)	break ;;
				esac
				case $1 in
				:)	break ;;
				esac
				shift
			done
			;;
		esac
		;;
	esac

	# NOTE() support

	case $ext in
	*"<stdio.h>"*)	
		case $ext in
		*"#define NOTE("*)
			;;
		*)	ext="$ext
#define NOTE(s)	do{write(9,\" \",1);write(9,s,strlen(s));write(9,\" ...\",4);}while(0)"
			;;
		esac
		;;
	esac

	# save $* for ancient shells

	argx=1
	argv=$*

	# loop on all candidate groups

	while	:
	do
		# check the candidate macros

		cc="$cc $mac"

		# check for global default headers (some cc -E insist on compiling)

		case $hdrtest in
		'')	hdrtest=1
			allinc=
			for x in types
			do	case $config in
				0)	c=_sys_${x}
					;;
				1)	case $shell in
					ksh)	typeset -u u=$x ;;
					*)	u=`echo $x | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
					esac
					c=HAVE_SYS_${u}_H
					;;
				esac
				x=sys/$x.h
				echo "${allinc}#include <$x>" > $tmp.c
				if	is_hdr $x
				then	gothdr="$gothdr + $x"
					case $explicit in
					0)	can="$can$cansep#define $c	1	/* #include <$x> ok */"
						nan="$nan$cansep$c=1"
						cansep=$nl
						;;
					esac
					eval $c=1
					allinc="${allinc}#include <$x>$nl"
				else	gothdr="$gothdr - $x"
					case $explicit$all$config$undef in
					0?1?|0??1)
						can="$can$cansep#undef	$c		/* #include <$x> not ok */"
						nan="$nan$cansep$c="
						cansep=$nl
						;;
					01??)	can="$can$cansep#define $c	0	/* #include <$x> not ok */"
						nan="$nan$cansep$c=0"
						cansep=$nl
						;;
					esac
				fi
			done
			;;
		esac

		# add implicit headers/libraries before the checks

		case $op in
		npt)	hdr="sys/types.h stdlib.h unistd.h $hdr"
			;;
		siz|typ)hdr="sys/types.h time.h sys/time.h sys/times.h stddef.h stdlib.h $hdr"
			;;
		esac

		# check the candidate headers

		case $hdr in
		?*)	z=$hdr
			hdr=
			dis=0
			for x in $z
			do	case $x in
				*.h)	case " $gothdr " in
					*" - $x "*)
						continue
						;;
					*" + $x "*)
						;;
					*)	case $shell in
						bsh)	eval `echo $x | sed -e 's,^\\([^\\\\/]*\\).*[\\\\/]\\([^\\\\/]*\\)\$,\\1_\\2,' -e 's/\\..*//' -e 's/^/c=/'`
							;;
						*)	eval 'c=${x##*[\\/]}'
							eval 'c=${c%%.*}'
							case $x in
							*/*)	eval 'c=${x%%[\\/]*}_${c}' ;;
							esac
							;;
						esac
						case $explicit in
						0)	dis=0
							;;
						*)	case $x in
							*/*)	dis=$c ;;
							*)	dis=hdr ;;
							esac
							case ${dis}_ in
							${op}_*)dis=0 ;;
							*)	dis=1 ;;
							esac
							;;
						esac
						case $config in
						0)	case $x in
							*/*)	c=_${c} ;;
							*)	c=_hdr_${c} ;;
							esac
							;;
						1)	case $shell in
							ksh)	typeset -u u=$c ;;
							*)	u=`echo $c | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
							esac
							c=HAVE_${u}_H
							;;
						esac
						echo "${allinc}#include <$x>" > $tmp.c
						if	is_hdr $x
						then	gothdr="$gothdr + $x"
							case $dis in
							0)	can="$can$cansep#define $c	1	/* #include <$x> ok */"
								nan="$nan$cansep$c=1"
								cansep=$nl
								;;
							esac
							eval $c=1
						else	gothdr="$gothdr - $x"
							case $dis$all$config$undef in
							0?1?|0??1)
								can="$can$cansep#undef	$c		/* #include <$x> not ok */"
								nan="$nan$cansep$c="
								cansep=$nl
								;;
							01??)	can="$can$cansep#define $c	0	/* #include <$x> not ok */"
								nan="$nan$cansep$c=0"
								cansep=$nl
								;;
							esac
							continue
						fi
						;;
					esac
					;;
				*)	test -r $x || continue
					;;
				esac
				hdr="$hdr $x"
			done
			;;
		esac

		# check the candidate libraries

		case $lib in
		?*)	z=
			for p in $lib
			do	z="$p $z"
			done
			lib=
			p=
			hit=0
			echo "int main(){return(0);}" > $tmp.c
			for x in $z
			do	p=$x
				case " $gotlib " in
				*"- $p "*)
					failure +
					p=
					;;
				*"+ $p "*)
					success +
					lib="$p $lib"
					;;
				*)	rm -f $tmp.exe
					is LIB $p
					if	compile $cc -o $tmp.exe $tmp.c $p $lib <&$nullin >&$nullout
					then	success
						gotlib="$gotlib + $p"
						lib="$p $lib"
						e=0
					else	a=
						e=1
						for l in $z
						do	case $l in
							-)	a=
								continue
								;;
							$p)	a=$p
								continue
								;;
							*)	case $gotlib in
								*" $l "*)	continue ;;
								esac
								;;
							esac
							case $a in
							$p)	a="$a $l"
								if	compile $cc -o $tmp.exe $tmp.c $a <&$nullin >&$nullout
								then	success
									gotlib="$gotlib + $p"
									lib="$p $lib"
									e=0
									break
								fi
								;;
							esac
						done
						case $e in
						1)	failure
							gotlib="$gotlib - $p"
							;;
						esac
					fi
					y=
					for x in $p
					do	case $shell in
						bsh)	c=`echo X$x | sed 's,X-l,,'` ;;
						*)	eval 'c=${x#-l}' ;;
						esac
						case $c in
						*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*)
							c=`echo '' $c | sed -e 's,.*[\\\\/],,' -e 's,\.[^.]*$,,' -e 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_],_,g' -e '/^lib./s,^lib,,'`
							;;
						esac
						case $config in
						0)	case $e$p in
							0*' '*)	case " $gotlib " in
								*[-+]" $x "*)
									;;
								*)	can="$can$cansep#define _LIB_$c	1	/* $x is a library */"
									nan="$nan${cansep}_LIB_$c=1"
									cansep=$nl
									eval _LIB_$c=1
									;;
								esac
								;;
							esac
							;;
						1)	case $shell in
							ksh)	typeset -u u=$c ;;
							*)	u=`echo $c | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
							esac
							c=$u
							case $e in
							0*' '*)	case " $gotlib " in
								*[-+]" $x "*)
									;;
								*)	can="$can$cansep#define HAVE_${c}_LIB	1	/* $x is a library */"
									nan="$nan${cansep}HAVE_${c}_LIB=1"
									cansep=$nl
									eval HAVE_${c}_LIB=1
									;;
								esac
								;;
							esac
							;;
						esac
						y=${y}_$c
					done
					case $config in
					0)	c=_LIB${y} ;;
					1)	c=HAVE${y}_LIB ;;
					esac
					case $p in
					*' '*)	q="a library group" ;;
					*)	q="a library" ;;
					esac
					case $e in
					0)	can="$can$cansep#define $c	1	/* $p is $q */"
						nan="$nan$cansep$c=1"
						cansep=$nl
						eval $c=1
						case $hit in
						1)	break ;;
						esac
						;;
					1)	case $all$config$undef in
						?1?|??1)can="$can$cansep#undef	$c		/* $p is not $q */"
							nan="$nan$cansep$c="
							cansep=$nl
							;;
						1??)	can="$can$cansep#define $c	0	/* $p is not $q */"
							nan="$nan$cansep$c=0"
							cansep=$nl
							;;
						esac
						eval $c=0
						;;
					esac
					p=
					;;
				esac
			done
			;;
		esac

		# last op precheck

		case $op in
		ref)	deflib="$deflib $lib"
			defhdr="$defhdr $hdr"
			break
			;;
		esac
		IFS=" ,"
		case $shell in
		bash)	op=`echo $op`
			arg=`echo $arg`
			;;
		*)	eval op=\"$op\"
			eval arg=\"$arg\"
			;;
		esac
		IFS=$ifs

		# check for op aliases

		x=
		for o in $op
		do	case $o in
			def|default)	x="$x cmd dat hdr key lib mth sys typ" ;;
			*)		x="$x $o" ;;
			esac
		done

		# loop on the ops o and args a

		result=UNKNOWN
		for o in $x
		do	for a in $arg
			do	c=
				case $a in
				*[.\\/]*)
					case $o in
					hdr|lcl|nxt|pth|sys)
						x=$a
						case $x in
						*.lcl|*.nxt)
							case $o in
							sys)	x=sys/$x ;;
							esac
							case $shell in
							bsh)	eval `echo $x | sed 's,\\(.*\\)\.\\([^.]*\\),x=\\1 o=\\2,'`
								;;
							*)	o=${x##*.}
								x=${x%.${o}}
								;;
							esac
							v=$x
							;;
						esac
						case $x in
						*[\\/]*)case $shell in
							bsh)	eval `echo $x | sed 's,\\(.*\\)[\\\\//]\\(.*\\),p=\\1 v=\\2,'`
								;;
							*)	eval 'p=${x%/*}'
								eval 'v=${x##*/}'
								;;
							esac
							;;
						*.*)	case $shell in
							bsh)	eval `echo $x | sed 's,\\(.*\\)\\.\\(.*\\),p=\\1 v=\\2,'`
								;;
							*)	eval 'p=${x%.*}'
								eval 'v=${x##*.}'
								;;
							esac
							;;
						*)	p=
							;;
						esac
						case $o in
						lcl|nxt)	c=$v.$o ;;
						*)		c=$v ;;
						esac
						;;
					*)	case $shell in
						bsh)	eval `echo $a | sed -e 's,.*[\\\\/],,' -e 's/\\(.*\\)\\.\\(.*\\)/p=\\1 v=\\2/'`
							;;
						*)	eval 'p=${a%.*}'
							eval 'p=${p##*[\\/]}'
							eval 'v=${a##*.}'
							eval 'v=${v##*[\\/]}'
							;;
						esac
						;;
					esac
					case $p in
					'')	f=${v} ;;
					*)	f=${p}/${v} ;;
					esac
					case $o in
					run)	v=$p
						p=
						m=_${v}
						;;
					mem)	case $p in
						*.*)	case $shell in
							bsh)	eval `echo $p | sed 's/\\([^.]*\\)\\.\\(.*\\)/p=\\1 m=\\2/'`
								;;
							*)	eval 'm=${p#*.}'
								eval 'p=${p%%.*}'
								;;
							esac
							v=${m}.${v}
						esac
						case $config in
						0)	m=_${v}_${p} ;;
						1)	m=_${v}_in_${p} ;;
						esac
						;;
					*)	case $p in
						'')	m=_${v} ;;
						*)	m=_${p}_${v} ;;
						esac
						;;
					esac
					;;
				*)	p=
					v=$a
					f=$a
					m=_${v}
					;;
				esac
				case $c in
				'')	c=$v ;;
				esac
				M=$m
				case $o in
				out)	case $a in
					-)	a=-
						;;
					?*)	test="$a $test"
						a=
						;;
					esac
					;;
				*)	case " $idyes " in
					*" $m "*)
						i=1
						;;
					*)	case " $idno " in
						*" $m "*)
							i=0
							;;
						*)	case $m in
							*'*')	m=`echo "$m" | sed 's,\*,_ptr,g'` ;;
							esac
							case $m in
							*[-+/\\]*)
								i=0
								;;
							*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*)
								is id $m
								copy $tmp.c "int $m = 0;"
								if	compile $cc -c $tmp.c
								then	success -
									idyes="$idyes $m"
									i=1
								else	failure -
									idno="$idno $m"
									i=0
								fi
								;;
							*)	i=1
								;;
							esac
							;;
						esac
						case $i in
						0)	case $o in
							dat|dfn|key|lib|mac|mth|nos|npt|siz|sym|typ|val)
								continue
								;;
							esac
							;;
						esac
						;;
					esac
					;;
				esac
				case $m in
				*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*)
					m=`echo "X$m" | sed -e 's,^.,,' -e 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_],_,g'`
					;;
				esac

				# check output redirection

				case $out in
				$cur)	;;
				*)	case $cur in
					$a|$c)	;;
					*)	case $cur in
						.)	;;
						*)	case $vers in
							?*)	echo
								for api in $vers
								do	API=`echo $api | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ`
									eval ver='${'ver_${api}'}'
									echo "#define ${API}_VERSION	${ver}"
								done
							esac
							case $apis in
							?*)	for api in $apis
								do	API=`echo $api | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ`
									echo "#define ${API}API(rel)	( _BLD_${api} || !_API_${api} || _API_${api} >= rel )"
									map=
									sep=
									eval syms='"${'api_sym_${api}'}"'
									# old solaris requires -k<space><junk> #
									set x x `echo "$syms" | sort -t: -u -k 1,1 -k 2,2nr 2>/dev/null | sed 's/:/ /'`
									case $# in
									2)	# ancient sort doesn't have -k #
										set x x `echo "$syms" | sort -t: -u +0 -1 +1 -2nr 2>/dev/null | sed 's/:/ /'`
										;;
									esac
									sym=
									while	:
									do	shift 2
										case $# in
										[01])	break ;;
										esac
										prv=$sym
										sym=$1
										rel=$2
										case $prv in
										$sym)	echo "#elif _API_${api} >= $rel"
											;;
										*)	case $prv in
											'')	echo
												echo "#if !defined(_API_${api}) && defined(_API_DEFAULT)"
												echo "#define _API_${api}	_API_DEFAULT"
												echo "#endif"
												;;
											*)	echo "#endif"
												;;
											esac
											echo
											echo "#if ${API}API($rel)"
											;;
										esac
										echo "#undef	${sym}"
										echo "#define ${sym}	${sym}_${rel}"
										map=$map$sep${sym}_${rel}
										sep=' '
									done
									echo "#endif"
									echo
									echo "#define _API_${api}_MAP	\"$map\""
								done
								echo
								;;
							esac
							case $iff in
							?*)	echo "#endif" ;;
							esac
							case $cur in
							-)	;;
							*)	exec >/dev/null
								case $cur in
								*[\\/]*|*.h)	x=$cur ;;
								*)		x=$dir/$cur ;;
								esac
								case $define in
								n)	sed '/^#/d' $tmp.h > $tmp.c
									sed '/^#/d' $x > $tmp.t
									;;
								*)	(proto -r $protoflags $tmp.h) >/dev/null 2>&1
									sed 's,/\*[^/]*\*/, ,g' $tmp.h > $tmp.c
									sed 's,/\*[^/]*\*/, ,g' $x > $tmp.t
									;;
								esac
								if	cmp -s $tmp.c $tmp.t
								then	rm -f $tmp.h
									case $verbose in
									1)	echo "$command: $x: unchanged" >&$stderr ;;
									esac
								else	case $x in
									${dir}[\\/]$cur)	test -d $dir || mkdir $dir || exit 1 ;;
									esac
									mv $tmp.h $x
								fi
								;;
							esac
							;;
						esac
						case $out in
						+)	case $status in
							1)	;;
							*)	status=0 ;;
							esac
							exit $status
							;;
						-)	eval "exec >&$stdout"
							;;
						*)	exec >$tmp.h
							;;
						esac
						case $out in
						"")	case $a in
							*[\\/]*|???????????????*) cur=$c ;;
							*)			cur=$a ;;
							esac
							;;
						*)	cur=$out
							;;
						esac
						case $in in
						""|-|+)	case $o in
							run)	x=" from $a" ;;
							*)	x= ;;
							esac
							;;
						*)	x=" from $in"
							;;
						esac

						# output header comments

						case $define in
						n)	;;
						?)	echo "/* : : generated$x by $command version $version : : */"
							for x in $pragma
							do	echo "#pragma $x"
							done
							case $out in
							""|-|+)	x=$m
								;;
							*.*)	case $shell in
								bsh)	eval `echo $in | sed -e 's,\\.,_,g' -e 's/^/x=/'`
									;;
								*)	i=$out
									x=_
									while	:
									do	case $i in
										*.*)	eval 'x=$x${i%%.*}_'
											eval 'i=${i#*.}'
											;;
										*)	x=$x$i
											break
											;;
										esac
									done
									;;
								esac
								;;
							*)	x=_$out
								;;
							esac
							case $o in
							iff)	case $M in
								""|*-*)	 ;;
								*)	iff=${m}_H ;;
								esac
								;;
							*)	case $regress in
								'')	case $x in
									*-*)	;;
									*)	x=`pwd | sed -e 's,.*[\\\\/],,' -e 's,\\..*,,' -e 's,^lib,,' -e 's,^,'${x}_',' -e 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_],_,g'`
										# ksh n+ bug workaround
										case $x in
										*[!_]*)	;;
										*)	x=_$$ ;;
										esac
										iff=_def${x}
										;;
									esac
									;;
								*)	case $x in
									*-*)	;;
									*)	iff=_REGRESS
										;;
									esac
									;;
								esac
								;;
							esac
							case $iff in
							?*)	echo "#ifndef $iff"
								echo "#define $iff	1"
								;;
							esac
							;;
						esac
						;;
					esac
					;;
				esac
				case $can in
				?*)	case $define in
					1)	echo "$can" ;;
					n)	echo "$nan" ;;
					esac
					can=
					nan=
					cansep=
					;;
				esac

				# set up the candidate include list

				pre=
				inc=
				for x in $defhdr - $hdr
				do	case $x in
					-)	case $pre in
						?*)	continue ;;
						esac
						case $v in
						*.*)	for x in `echo $v | sed 's,\\., ,g'`
							do	pre="$pre
#undef	$x"
							done
							;;
						*)	case $o in
							siz|typ)case $v in
								char|short|int|long)
									;;
								*)	pre="#undef	$v"
									;;
								esac
								;;
							*)	pre="#undef	$v"
								;;
							esac
							;;
						esac
						;;
					*.h)	case $shell in
						bsh)	eval `echo $x | sed -e 's,^\\([^\\\\/]*\\).*[\\\\/]\\([^\\\\/]*\\)\$,\\1_\\2,' -e 's/\\..*//' -e 's/^/c=/'`
							;;
						*)	eval 'c=${x##*[\\/]}'
							eval 'c=${c%%.*}'
							case $x in
							*/*)	eval 'c=${x%%[\\/]*}_${c}' ;;
							esac
							;;
						esac
						case $config in
						0)	case $x in
							*/*)	c=_${c} ;;
							*)	c=_hdr_${c} ;;
							esac
							;;
						1)	case $shell in
							ksh)	typeset -u u=$c ;;
							*)	u=`echo $c | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
							esac
							c=HAVE_${u}_H
							;;
						esac
						case " $puthdr " in
						*" $c "*)
							;;
						*)	puthdr="$puthdr $c"
							usr="$usr$nl#define $c 1"
							;;
						esac
						inc="$inc
#include <$x>"
						;;
					esac
				done

				# set up the candidate lib list

				for x in $lib $deflib
				do	case $shell in
					ksh)	eval 'c=${x#-l}' ;;
					*)	c=`echo X$x | sed 's,X-l,,'` ;;
					esac
					case $c in
					*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*)
						c=`echo '' $c | sed -e 's,.*[\\\\/],,' -e 's,\.[^.]*$,,' -e 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_],_,g' -e '/^lib./s,^lib,,'`
						;;
					esac
					case $config in
					0)	c=_LIB_${c}
						;;
					1)	case $shell in
						ksh)	typeset -u u=$c ;;
						*)	u=`echo $c | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
						esac
						c=HAVE_${u}_LIB
						;;
					esac
					case " $putlib " in
					*" $c "*)
						;;
					*)	putlib="$putlib $c"
						usr="$usr$nl#define $c 1"
						;;
					esac
				done

				# src overrides builtin test

				case $config:$def in
				0:)	case $o in
					tst|var);;
					*)	m=_${o}${m} ;;
					esac
					;;
				1:)	case $o in
					tst|var)m=${v} ;;
					esac
					case $shell in
					ksh)	typeset -u u=$m ;;
					*)	u=`echo $m | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
					esac
					case $o in
					tst|var)case $m in
						$u)	;;
						*)	case $m in
							hdr_*|lib_*|sys_*)
								case $shell in
								ksh)	u=${u#????} ;;
								*)	u=`echo $u | sed 's/....//'` ;;
								esac
								;;
							esac
							m=HAVE_${u}
							;;
						esac
						;;
					dat)	m=HAVE${u}_DATA ;;
					hdr|lcl)m=HAVE${u}_H ;;
					key)	m=HAVE${u}_RESERVED ;;
					mth)	m=HAVE${u}_MATH ;;
					npt)	m=HAVE${u}_DECL ;;
					pth)	m=${u}_PATH
						case $shell in
						ksh)	m=${m#_} ;;
						*)	m=`echo $m | sed 's,^_,,'` ;;
						esac
						;;
					nxt)	m=HAVE${u}_NEXT ;;
					siz)	m=SIZEOF${u} ;;
					sys)	m=HAVE_SYS${u}_H ;;
					*)	m=HAVE${u} ;;
					esac
					;;
				*)	m=$def
					M=$m
					;;
				esac
				case $src in
				?*)	case $src in
					$noext)	EXT= ;;
					*)	EXT="$tst
$ext"
						;;
					esac
					copy $tmp.c "$std
$EXT
$usr
$inc
$src
"
					V=1
					e=0
					is tst "${note:-$run}"
					case $run in
					cat*|nocat*)
						copy - "$src"
						;;
					cross*|nocross*)
						copy $tmp.sh "$src"
						chmod +x $tmp.sh
						execute $tmp.sh <&$nullin || e=1
						;;
					run*|norun*)
						(eval "$src") <&$nullin || e=1
						;;
					mac*|nomac*)
						if	compile $cc -E -P $tmp.c <&$nullin >$tmp.i
						then	sed -e '/<<[ 	]*".*"[ 	]*>>/!d' -e 's/<<[ 	]*"//g' -e 's/"[ 	]*>>//g' $tmp.i
						else	e=1
						fi
						;;
					p*|nop*)compile $cc -DTEST=$p -DID=$v -E $tmp.c <&$nullin >&$nullout || e=1
						;;
					c*|noc*)compile $cc -DTEST=$p -DID=$v -c $tmp.c <&$nullin >&$nullout || e=1
						;;
					*)	case $run in
						status*)ccflags=
							;;
						s*|nos*)case $reallystatictest in
							'')	#UNDENT...

			reallystatictest=.
			echo "$tst
$ext
int main(){printf("hello");return(0);}" > ${tmp}s.c
			rm -f ${tmp}s.exe
			if	compile $cc -c ${tmp}s.c <&$nullin >&$nullout &&
				compile $cc -o ${tmp}s.exe ${tmp}s.o <&$nullin >&$nullout 2>${tmp}s.e &&
				$executable ${tmp}s.exe
			then	e=`wc -l ${tmp}s.e`
				eval set x x $binding
				while	:
				do	shift
					shift
					case $# in
					0)	break ;;
					esac
					rm -f ${tmp}s.exe
					compile $cc -o ${tmp}s.exe $1 ${tmp}s.o <&$nullin >&$nullout 2>${tmp}s.e && $executable ${tmp}s.exe || continue
					case `wc -l ${tmp}s.e` in
					$e)	;;
					*)	continue ;;
					esac
					d=`ls -s ${tmp}s.exe`
					rm -f ${tmp}s.exe
					compile $cc -o ${tmp}s.exe $2 ${tmp}s.o <&$nullin >&$nullout 2>${tmp}s.e && $executable ${tmp}s.exe || continue
					case `wc -l ${tmp}s.e` in
					$e)	;;
					*)	continue ;;
					esac
					case `ls -s ${tmp}s.exe` in
					$d)	;;
					*)	reallystatic=$2
						set x
						shift
						break
						;;
					esac
				done
			fi
			rm -f ${tmp}s.*
								#...INDENT
								;;
							esac
							ccflags=$reallystatic
							;;
						*)	ccflags=
							;;
						esac
						set x $mac
						e=1
						while	:
						do	o=
							shift
							while	:
							do	case $# in
								0)	break ;;
								esac
								case $1 in
								-)	break ;;
								esac
								o="$o $1"
								shift
							done
							rm -f $tmp.exe
							if	compile $cc $ccflags $o -DTEST=$p -DID=$v -o $tmp.exe $tmp.c $lib $deflib <&$nullin >&$nullout && $executable $tmp.exe
							then	case $run in

				status*)execute $tmp.exe <&$nullin >&$nullout
					V=$?
					case $V in
					0)	e=1 ;;
					*)	e=0 ;;
					esac
					break
					;;
				no[ls]*);;
				[ls]*)	e=0 && break ;;
				noo*)	execute $tmp.exe <&$nullin >$tmp.out || break ;;
				o*)	execute $tmp.exe <&$nullin >$tmp.out && e=0 && break ;;
				no*)	execute $tmp.exe <&$nullin >&$nullout || break ;;
				*)	execute $tmp.exe <&$nullin >&$nullout && e=0 && break ;;

								esac
							else	case $run in
								no[els]*)e=1 && break ;;
								esac
							fi
							case $# in
							0)	case $run in
								no*)	e=0 ;;
								esac
								break
								;;
							esac
						done
						;;
					esac
					o=1
					case $run in
					no*)	case $e in
						0)	e=1 ;;
						*)	e=0 ;;
						esac
						;;
					esac
					case $run in
					o*|noo*)case $e in
						0)	cat $tmp.out ;;
						esac
						rm -f $tmp.out
						;;
					esac
					report $e $V "${note:-$run\ passed}" "${note:-$run} failed"
					continue
					;;
				esac

				# initialize common builtin state

				case $o in
				dat|lib|mth|run)
					case $statictest in
					"")	statictest=FoobaR
						copy $tmp.c "
$tst
$ext
$std
$usr
_BEGIN_EXTERNS_
extern int $statictest;
_END_EXTERNS_
int main(){char* i = (char*)&$statictest; return ((unsigned int)i)^0xaaaa;}
"
						rm -f $tmp.exe
						if	compile $cc -o $tmp.exe $tmp.c <&$nullin >&$nullout && $executable $tmp.exe
						then	case $static in
							.)	static=
								copy $tmp.c "
$tst
$ext
int main(){printf("hello");return(0);}
"
								rm -f $tmp.exe
								if	compile $cc -c $tmp.c <&$nullin >&$nullout &&
									compile $cc -o $tmp.exe $tmp.o <&$nullin >&$nullout &&
									$executable $tmp.exe
								then	e=`wc -l $tmp.e`
									eval set x x $binding
									while	:
									do	shift
										shift
										case $# in
										0)	break ;;
										esac
										rm -f $tmp.exe
										compile $cc -o $tmp.exe $1 $tmp.o <&$nullin >&$nullout && $executable $tmp.exe || continue
										case `wc -l $tmp.e` in
										$e)	;;
										*)	continue ;;
										esac
										d=`ls -s $tmp.exe`
										rm -f $tmp.exe
										compile $cc -o $tmp.exe $2 $tmp.o <&$nullin >&$nullout && $executable $tmp.exe || continue
										case `wc -l $tmp.e` in
										$e)	;;
										*)	continue ;;
										esac
										case `ls -s $tmp.exe` in
										$d)	;;
										*)	static=$2
											set x
											shift
											break
											;;
										esac
									done
								fi
								;;
							esac
						else	static=
						fi
						;;
					esac
					;;
				esac

				# builtin tests

				case $o in
				api)	;;
				cmd)	case $p in
					?*)	continue ;;
					esac
					is $o $a
					k=1
					for j in "" usr
					do	case $j in
						"")	d= s= ;;
						*)	d=/$j s=_$j ;;
						esac
						for i in bin etc ucb
						do	if	test -f $altroot/$d/$i/$a
							then	case $k in
								1)	k=0
									case $M in
									*-*)	;;
									*)	usr="$usr$nl#define $m 1"
										case $define in
										1)	echo "#define $m	1	/* $a in ?(/usr)/(bin|etc|ucb) */" ;;
										n)	echo "$m=1" ;;
										esac
										;;
									esac
									;;
								esac
								c=${s}_${i}_${v}
								usr="$usr$nl#define $c 1"
								case $define in
								1)	echo "#define $c	1	/* $d/$i/$a found */" ;;
								n)	echo "$c=1" ;;
								esac
							fi
						done
					done
					case $k in
					0)	success ;;
					1)	failure ;;
					esac
					;;
				dat)	case $p in
					?*)	continue ;;
					esac
					{
					copy - "
$tst
$ext
$std
$usr
$pre
"
					case $inc in
					?*)	echo "$inc"
						;;
					*)	echo "_BEGIN_EXTERNS_
extern int $v;
_END_EXTERNS_"
						;;
					esac
					echo "
#ifdef _DLL
#define _REF_
#else
#define _REF_	&
#endif
int main(){char* i = (char*) _REF_ $v; return ((unsigned int)i)^0xaaaa;}"
					} > $tmp.c
					is $o $v
					rm -f $tmp.exe
					compile $cc -c $tmp.c <&$nullin >&$nullout &&
					compile $cc $static -o $tmp.exe $tmp.o $lib $deflib <&$nullin >&$nullout &&
					$executable $tmp.exe
					report $? 1 "$v in default lib(s)" "$v not in default lib(s)"
					;;
				dfn)	case $p in
					?*)	continue ;;
					esac
					is dfn $v
					echo "$pre
$tst
$ext
$inc
#ifdef $v
<<\"#ifndef $v\">>
<<\"#define $v\">>	$v	<<\"/* native $v */\">>
<<\"#endif\">>
#endif" > $tmp.c
					if	compile $cc -E -P $tmp.c <&$nullin >$tmp.i
					then	sed -e '/<<[ 	]*".*"[ 	]*>>/!d' -e 's/<<[ 	]*"//g' -e 's/"[ 	]*>>//g' $tmp.i > $tmp.t
						if	test -s $tmp.t
						then	success
							cat $tmp.t
						else	failure
						fi
					else	failure
					fi
					;;
				exp)	case $test in
					'')	echo "$command: $file$sline: test expression expected for $o" >&$stderr
						exit 1
						;;
					esac
					case $a in
					-|'')	;;
					*)	eval x='$'$a
						case $x in
						1)	result=FAILURE
							continue
							;;
						esac
						;;
					esac
					case $test in
					[01]|'"'*'"'|'<'*'>')
						case $a in
						-|'')	;;
						*)	case $define$note in
							1)	echo "#define $a	$test" ;;
							1*)	echo "#define $a	$test	/* $note */" ;;
							n)	echo "$a=$test" ;;
							esac
							eval $a='$test'
							;;
						esac
						;;
					*)	case $note in
						'')	note=$test ;;
						esac
						case $test in
						'')	c=1
							;;
						*)	is exp "$note"
							x=
							for i in `echo '' $test | sed 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_], & ,g'`
							do	case $i in
								[\ \	])
									;;
								[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_]*)
									eval i='${'$i'}'
									case $i in
									'')	i=0
										;;
									'"'*'"');;
									*[!-+0123456789]*)
										case $i in
										*'"'*)	i=1 ;;
										*)	i='"'$i'"' ;;
										esac
										;;
									esac
									x="$x $i"
									;;
								'!')	x="$x 0 ="
									;;
								'&'|'|')case $x in
									*"$i")	;;
									*)	x="$x \\$i" ;;
									esac
									;;
								*)	x="$x \\$i"
									;;
								esac
							done
							c=`eval expr $x 2>&$stderr`
							;;
						esac
						case $c in
						0)	c=1 ;;
						*)	c=0 ;;
						esac
						M=$a
						m=$a
						report $c 1 "$note is true" "$note is false"
						;;
					esac
					;;
				hdr|lcl|nxt|sys)
					case $o in
					lcl|nxt)case $M in
						*-*)	continue ;;
						esac
						eval x='$'_$m
						case $x in
						?*)	continue ;;
						esac
						eval _$m=1
						is $o $f
						echo "$pre
$tst
$ext
$inc
#include <$f.h>" > $tmp.c
						case $f in
						sys/*)	e= ;;
						*)	e='-e /[\\\\\/]sys[\\\\\/]'$f'\\.h"/d' ;;
						esac
						if	compile $cc -E $tmp.c <&$nullin >$tmp.i
						then	i=`sed -e '/^#[line 	]*[0123456789][0123456789]*[ 	][ 	]*"[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:]*[\\\\\/].*[\\\\\/]'$f'\\.h"/!d' $e -e s'/.*"\\(.*\\)".*/\\1/' -e 's,\\\\,/,g' -e 's,///*,/,g' $tmp.i | sed 1q`
							case $i in
							[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]:[\\/]*)
								;;
							*/*/*)	k=`echo "$i" | sed 's,.*/\([^/]*/[^/]*\)$,../\1,'`
								echo "$pre
$tst
$ext
$inc
#include <$k>" > $tmp.c
								if	compile $cc -E $tmp.c <&$nullin >$tmp.i
								then	j=`sed -e '/^#[line 	]*[0123456789][0123456789]*[ 	][ 	]*"[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:]*[\\\\\/].*[\\\\\/]'$f'\\.h"/!d' $e -e s'/.*"\\(.*\\)".*/\\1/' -e 's,\\\\,/,g' -e 's,///*,/,g' $tmp.i | sed 1q`
									wi=`wc < "$i"`
									wj=`wc < "$j"`
									case $wi in
									$wj)	i=$k	;;
									esac
								fi
								;;
							*)	echo "$pre
$tst
$ext
$inc
#include <../include/$f.h>" > $tmp.c
								if	compile $cc -E $tmp.c <&$nullin >&$nullout
								then	i=../include/$f.h
								fi
								;;
							esac
						else	i=
						fi
						case $i in
						[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]:[\\/]*|[\\/]*)
							success
							case $o in
							lcl)	echo "#if defined(__STDPP__directive)"
								echo "__STDPP__directive pragma pp:hosted"
								echo "#endif"
								echo "#include <$i>	/* the native <$f.h> */"
								echo "#undef	$m"
								usr="$usr$nl#define $m 1"
								echo "#define $m	1"
								;;
							nxt)	echo "#define $m <$i>	/* include path for the native <$f.h> */"
								echo "#define ${m}_str \"$i\"	/* include string for the native <$f.h> */"
								usr="$usr$nl#define $m <$i>$nl#define ${m}_str \"$i\""
								eval $m=\\\<$i\\\>
								;;
							esac
							break
							;;
						../*/*)	success
							case $o in
							lcl)	echo "#include <$i>	/* the native <$f.h> */"
								echo "#undef	$m"
								usr="$usr$nl#define $m 1"
								echo "#define $m	1"
								eval $m=1
								;;
							nxt)	echo "#define $m <$i>	/* include path for the native <$f.h> */"
								echo "#define ${m}_str \"$i\"	/* include string for the native <$f.h> */"
								usr="$usr$nl#define $m <$i>$nl#define ${m}_str \"$i\""
								eval $m=\\\<$i\\\>
								;;
							esac
							break
							;;
						*)	failure
							case $o in
							lcl)	case $all$config$undef in
								?1?|??1)echo "#undef	$m		/* no native <$f.h> */" ;;
								1??)	echo "#define $m	0	/* no native <$f.h> */" ;;
								esac
								eval $m=0
								;;
							nxt)	case $all$config$undef in
								?1?|??1)echo "#undef	$m		/* no include path for the native <$f.h> */" ;;
								esac
								;;
							esac
							;;
						esac
						;;
					*)	case $o in
						hdr)	x=$f.h ;;
						sys)	x=sys/$f.h ;;
						esac
						case " $gothdr " in
						*" - $x "*)
							failure +
							;;
						*" + $x "*)
							success +
							;;
						*)	echo "
$tst
$ext
$allinc
$inc
#include <$x>" > $tmp.c
							if	is_hdr $x
							then	gothdr="$gothdr + $x"
								case $M in
								*-*)	;;
								*)	case " $puthdr " in
									*" $m "*)
										;;
									*)	puthdr="$puthdr $m"
										usr="$usr$nl#define $m 1"
										;;
									esac
									case $define in
									1)	echo "#define $m	1	/* #include <$x> ok */" ;;
									n)	echo "$m=1" ;;
									esac
									eval $m=1
									;;
								esac
							else	gothdr="$gothdr - $x"
								case $M in
								*-*)	;;
								*)	case $define$all$config$undef in
									1?1?|1??1)echo "#undef	$m		/* #include <$x> not ok */" ;;
									11??)	echo "#define $m	0	/* #include <$x> not ok */" ;;
									n1?1)	echo "$m=" ;;
									n1??)	echo "$m=0" ;;
									esac
									eval $m=0
									;;
								esac
							fi
							;;
						esac
						continue
						;;
					esac
					;;
				iff)	;;
				ini)	;;
				key)	case $p in
					?*)	continue ;;
					esac
					w=$v
					while	:
					do	is $o $w
						echo "$pre
$tst
$ext
int f(){int $w = 1;return($w);}" > $tmp.c
						if	compile $cc -c $tmp.c <&$nullin >&$nullout
						then	failure
							case $set in
							*" ="|*" = "*)
								set x $set
								shift
								w=
								while	:
								do	case $# in
									0)	break ;;
									esac
									case $1 in
									=)	break ;;
									esac
									case $w in
									'')	w=$1 ;;
									*)	w="$w $1" ;;
									esac
									shift
								done
								case $1 in
								=)	shift
									case $# in
									0)	set=" " ;;
									*)	set=$* ;;
									esac
									;;
								*)	set=
									;;
								esac
								case $shell in
								ksh)	typeset -u u=$w ;;
								*)	u=`echo $w | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ` ;;
								esac
								u=_$u
								M=$w
								case $M in
								*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*)
									M=`echo "X$m" | sed -e 's,^.,,' -e 's,[^abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_],_,g'`
									;;
								esac
								case $config in
								1)	m=HAVE${u}_RESERVED ;;
								*)	m=_key_${w} ;;
								esac
								continue
								;;
							esac
							report - 1 - - "$w is not a reserved keyword" "default for reserved keyword $v"
						else	report 0 1 "$w is a reserved keyword" -
							case $M in
							*-*)	;;
							*)	case $define$w in
								1$v)	;;
								1*)	echo "#define $v	$w	/* alternate for reserved keyword $v */" ;;
								n*)	echo "$v=$w" ;;
								esac
								;;
							esac
						fi
						break
					done
					;;
				lib|mth)case $p in
					?*)	continue ;;
					esac
					case $v in
					-)	continue ;;
					esac
					is $o $v
					copy $tmp.c "
$tst
$ext
$std
$usr
$pre
$inc
typedef int (*_IFFE_fun)();
#ifdef _IFFE_extern
_BEGIN_EXTERNS_
extern int $v();
_END_EXTERNS_
#endif
static _IFFE_fun i=(_IFFE_fun)$v;int main(){return ((unsigned int)i)^0xaaaa;}
"
					d=-D_IFFE_extern
					if	compile $cc -c $tmp.c <&$nullin >&$nullout
					then	d=
					elif	compile $cc $d -c $tmp.c <&$nullin >&$nullout
					then	:
					else	d=error
					fi
					if	test error != "$d"
					then	rm -f $tmp.exe
						if	compile $cc $d $static -o $tmp.exe $tmp.o $lib $deflib <&$nullin >&$nullout &&
							$executable $tmp.exe
						then	case $o in
							lib)	c=0 ;;
							*)	c=1 ;;
							esac
							report $c 1 "$v() in default lib(s)" "$v() not in default lib(s)" "default for function $v()"
						else	case $o in
							mth)	rm -f $tmp.exe
								compile $cc $d $static -o $tmp.exe $tmp.o -lm <&$nullin >&$nullout &&
								$executable $tmp.exe
								report $? 1 "$v() in math lib" "$v() not in math lib" "default for function $v()"
								;;
							*)	report 1 1 - "$v() not in default lib(s)" "default for function $v()"
								;;
							esac
						fi
					else	case $intrinsic in
						'')	copy $tmp.c "
$tst
$ext
$std
$usr
$pre
$inc
_BEGIN_EXTERNS_
extern int foo();
_END_EXTERNS_
static int ((*i)())=foo;int main(){return(i==0);}
"
							compile $cc -c $tmp.c <&$nullin >&$nullout
							intrinsic=$?
							;;
						esac
						case $o in
						mth)	report $intrinsic 1 "$v() in math lib" "$v() not in math lib" "default for function $v()" ;;
						*)	report $intrinsic 1 "$v() in default lib(s)" "$v() not in default lib(s)" "default for function $v()" ;;
						esac
					fi
					;;
				mac)	case $p in
					?*)	continue ;;
					esac
					is mac $v
					echo "
$tst
$ext
$pre
$inc
#ifdef $v
'$m:$v'
#endif" > $tmp.c
					compile $cc -E $tmp.c <&$nullin | grep -c "'$m:$v'" >&$nullout
					report $? 1 "$v is a macro" "$v is not a macro" "default for macro $v"
					;;
				mem)	case $p in
					?*)	eval i='$'_iffe_typedef_$p
						case $i in
						0|1)	;;
						*)	echo "$pre
$tst
$ext
$inc
static $p i;
int n = sizeof(i);" > $tmp.c
							is typ $p
							if	compile $cc -c $tmp.c <&$nullin >&$nullout
							then	success -
								eval _iffe_typedef_$p=1
								i=1
							else	failure -
								eval _iffe_typedef_$p=0
								i=0
							fi
							;;
						esac
						case $i in
						0)	i="$v is not a member of $p" p="struct $p" ;;
						*)	i=- ;;
						esac
						is mem $v "$p"
						echo "$pre
$tst
$ext
$inc
static $p i;
int n = sizeof(i.$v);" > $tmp.c
						compile $cc -c $tmp.c <&$nullin >&$nullout
						report $? 1 "$v is a member of $p" "$i"
						;;
					*)	p=$v
						eval i='$'_iffe_typedef_$p
						case $i in
						0|1)	;;
						*)	echo "$pre
$tst
$ext
$inc
static $p i;
int n = sizeof(i);" > $tmp.c
							is typ $p
							if	compile $cc -c $tmp.c <&$nullin >&$nullout
							then	success -
								eval _iffe_typedef_$p=1
								i=1
							else	failure -
								eval _iffe_typedef_$p=0
								i=0
							fi
							;;
						esac
						case $i in
						0)	i="$p is not a non-opaque struct" p="struct $p" ;;
						*)	i=- ;;
						esac
						is nos "$p"
						echo "$pre
$tst
$ext
$inc
static $p i;
int n = sizeof(i);" > $tmp.c
						if	compile $cc -c $tmp.c <&$nullin >&$nullout
						then	echo "$pre
$tst
$ext
$inc
static $p i;
unsigned long f() { return (unsigned long)i; }" > $tmp.c
							if	compile $cc -c $tmp.c <&$nullin >&$nullout
							then	c=1
							else	c=0
							fi
						else	c=1
						fi
						report $c 1 "$p is a non-opaque struct" "$i"
					esac
					;;
				nop)	;;
				npt)	is npt $v
					copy $tmp.c "
$tst
$ext
$std
$usr
$pre
$inc
_BEGIN_EXTERNS_
struct _iffe_struct { int _iffe_member; };
#if _STD_
extern struct _iffe_struct* $v(struct _iffe_struct*);
#else
extern struct _iffe_struct* $v();
#endif
_END_EXTERNS_
"
					# some compilers with -O only warn for invalid intrinsic prototypes
					case " $cc " in
					*" -O "*)	xx=`echo $cc | sed 's/ -O / /g'` ;;
					*)		xx=$cc ;;
					esac
					compile $xx -c $tmp.c <&$nullin >&$nullout
					report -$config $? 1 "$v() needs a prototype" "$v() does not need a prototype"
					;;
				num)	is num $v
					copy $tmp.c "
$tst
$ext
$std
$usr
$pre
$inc
_BEGIN_EXTERNS_
int _iffe_int = $v / 2;
_END_EXTERNS_
"
					compile $cc -c $tmp.c <&$nullin >&$nullout
					report $? 1 "$v is a numeric constant" "$v is not a numeric constant"
					;;
				one)	for i in $a $hdr
					do	x="#include <$i>"
						case " $gothdr " in
						*" - $i "*)
							continue
							;;
						*" + $i "*)
							;;
						*)	echo "$x" > $tmp.c
							if	is_hdr $x
							then	gothdr="$gothdr + $x"
							else	gothdr="$gothdr - $x"
								continue
							fi
							;;
						esac
						case $one in
						"")	one=$x
							;;
						*"$x"*)	break
							;;
						*)	echo "$one" > $tmp.c
							if	compile $cc -E $tmp.c <&$nullin >$tmp.i
							then	c=$i
								case $c in
								*[\\/]*)	c=`echo $c | sed 's,[\\\\/],[\\\\/],g'` ;;
								esac
								case `sed -e '/^#[line 	]*1[ 	][ 	]*"[\\\\\/].*[\\\\\/]'$c'"/!d' $tmp.i` in
								?*)	break ;;
								esac
							fi
							one="$one$nl$x"
							;;
						esac
						echo "$x"
						break
					done
					;;
				opt)	M=$m
					is opt $a
					case " $PACKAGE_OPTIONS " in
					*" $a "*)	c=0 ;;
					*)		c=1 ;;
					esac
					report $c 1 "$a is set in \$PACKAGE_OPTIONS" "$a is not set in \$PACKAGE_OPTIONS"
					;;
				out|output)
					;;
				pth)	is pth $a
					pkg $pth
					tab="  "
					e=
					f=
					for i in $pth
					do	case $i in
						'{')	e="${nl}}"
							l=
							x=i
							v="\$${x}"
							t=${nl}${tab}
							b="fnd()${nl}{${t}for ${x} in"
							;;
						'}')	b="${b}${t}do${tab}if $exists ${v}/\${1}${t}${tab}${tab}then${tab}f=${v}/\${1}${t}${tab}${tab}${tab}return${t}${tab}${tab}fi"
							e="${t}done${e}"
							eval "${b}${e}"
							fnd $a
							case $f in
							?*)	break ;;
							esac
							;;
						-)	b="${b}${t}do${tab}test \"${v}\" = '' -o -d \"${v}\" &&${t}${tab}${tab}"
							x=${x}i
							v="${v}\$${x}"
							b="${b}for ${x} in"
							e="${t}done${e}"
							t="${t}${tab}${tab}"
							;;
						*)	case $e in
							'')	if	$exists ${i}/${a}
								then	f=${i}/${a}
									break
								fi
								;;
							*)	case $i in
								/|.)	b="${b} ''" ;;
								*)	b="${b} /${i}" ;;
								esac
								;;
							esac
							;;
						esac
					done
					case $f in
					'')	case $set in
						' ')	f=$a ;;
						?*)	f=$set ;;
						esac
						;;
					esac
					case $f in
					'')	c=1
						;;
					*)	c=0
						f="\"$f\""
						;;
					esac
					report $c "$f" "${note:-$a path}" "$a path not found"
					;;
				run)	is run $a
					if	test ! -r $a
					then	failure not found
						case $verbose in
						0)	echo "$command: $file$line: $a: not found" >&$stderr ;;
						esac
						exit 1
					fi
					noisy
					case $a in
					*.c)	rm -f $tmp.exe
						{
						echo "$tst
$ext
$std
$usr
$inc"
						cat $a
						} > $tmp.c
						compile $cc -o $tmp.exe $tmp.c $lib $deflib <&$nullin >&$stderr 2>&$stderr &&
						$executable $tmp.exe &&
						execute $tmp.exe $opt <&$nullin
						;;
					*.sh)	{
						copy - ":
set \"cc='$cc' executable='$executable' id='$m' static='$static' tmp='$tmp'\" $opt $hdr $test"
						cat $a
						} > $tmp.sh
						chmod +x $tmp.sh
						( . $tmp.sh ) <&$nullin
						;;
					*)	false
						;;
					esac
					case $? in
					0)	success
						;;
					*)	failure cannot run
						case $verbose in
						0)	echo "$command: $file$line: $a: cannot run" >&$stderr ;;
						esac
						exit 1
						;;
					esac
					;;
				siz)	case $p in
					"")	x= ;;
					*)	x="$p " ;;
					esac
					is siz "$x$v"
					{
					case $p:$v in
					long:*|*:*[_0123456789]int[_0123456789]*)
						echo "$pre
$tst
$ext
$inc
static $x$v i;
$x$v f() {
$x$v v; i = 1; v = i;"
						echo "i = v * i; i = i / v; v = v + i; i = i - v;"
						case $v in
						float|double) ;;
						*)	echo "v <<= 4; i = v >> 2; i = 10; i = v % i; i |= v; v ^= i; i = 123; v &= i;" ;;
						esac
						echo "return v; }"
						;;
					*)	echo "$pre
$inc
struct xxx { $x$v mem; };
static struct xxx v;
struct xxx* f() { return &v; }"
						;;
					esac
					case $x in
					""|"struct "|"union ")
						echo "int g() { return 0; }"
						;;
					*)	echo "int g() { return sizeof($x$v)<=sizeof($v); }" ;;
					esac
					copy - "
int main() {
		f();
		g();
		printf(\"%u\\n\", sizeof($x$v));
		return 0;
}"
					} > $tmp.c
					rm -f $tmp.exe $tmp.dat
					if	compile $cc -o $tmp.exe $tmp.c $lib $deflib <&$nullin >&$nullout &&
						$executable $tmp.exe &&
						execute $tmp.exe > $tmp.dat
					then	z=`cat $tmp.dat`
						c=0
					else	z=0
						c=1
					fi
					report $c "$z" "sizeof($x$v)" "$x$v not a type with known size"
					;;
				sym)	case $test in
					"")	x=$v ;;
					*)	x=$test ;;
					esac
					echo "$pre
$tst
$ext
$inc
'=' $x '='" > $tmp.c
					compile $cc -E $tmp.c <&$nullin \
					| sed \
						-e "/'='/!d" \
						-e "s/'='//g" \
						-e 's/[ 	]//g' \
						-e 's/((([^()]*)))->/->/g' \
						-e 's/(([^()]*))->/->/g' \
						-e 's/([^()]*)->/->/g' \
						-e 's/\([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789]*\)\[/\
ary \1[/g' \
						-e 's/\([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789]*\)(/\
fun \1[/g' \
						-e 's/\*->\([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_]\)/->\
ptr \1/g' \
						-e 's/->\([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_]\)/->\
reg \1/g' \
						-e "/^$v\$/d" \
						-e 's/^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789]*$/\
nam &/g' \
					| sed \
						-e '/^... /!d' \
					| LC_ALL=C sort \
						-u \
					| sed \
						-e 's/\(...\) \([abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789]*\).*/#ifndef _\1_'$v'\
#define _\1_'$v' \2\
#define _\1_'$v'_str "\2"\
#endif/'
					;;
				typ)	case $p in
					"")	x= ;;
					*)	x="$p " ;;
					esac
					is typ "$x$v"
					{
					case $p:$v in
					long:*|*:*[_0123456789]int[_0123456789]*)
						echo "$pre
$tst
$ext
$inc
static $x$v i;
$x$v f() {
$x$v v; i = 1; v = i;"
						echo "i = v * i; i = i / v; v = v + i; i = i - v;"
						case $v in
						float|double) ;;
						*)	echo "v <<= 4; i = v >> 2; i = 10; i = v % i; i |= v; v ^= i; i = 123; v &= i;" ;;
						esac
						echo "return v; }"
						;;
					*)	echo "$pre
$tst
$ext
$inc
struct xxx { $x$v mem; };
static struct xxx v;
struct xxx* f() { return &v; }"
						;;
					esac
					case $x in
					""|"struct "|"union ")
						echo "int main() { f(); return 0; }" ;;
					*)	echo "int main() { f(); return sizeof($x$v)<=sizeof($v); }" ;;
					esac
					} > $tmp.c
					rm -f $tmp.exe
					compile $cc -o $tmp.exe $tmp.c $lib $deflib <&$nullin >&$nullout &&
					$executable $tmp.exe &&
					execute $tmp.exe
					report $? 1 "$x$v is a type" "$x$v is not a type" "default for type $x$v"
					;;
				val)	case $arg in
					'"'*'"')echo $arg=\'$val\' ;;
					*)	echo $arg=\"$val\" ;;
					esac
					;;
				ver)	;;
				0)	result=FAILURE
					;;
				1)	result=SUCCESS
					;;
				:)	;;
				-)	;;
				*)	echo "$command: $file$line: $o: unknown feature test" >&$stderr
					status=1
					;;
				esac
			done
		done
		case $not in
		1)	case $result in
			FAILURE)	result=SUCCESS ;;
			*)		result=FAILURE ;;
			esac
			;;
		esac
		case $result in
		FAILURE)	user_pf=$fail user_yn=$no ;;
		*)		user_pf=$pass user_yn=$yes ;;
		esac
		case $user_pf in
		?*)	eval "$user_pf" <&$nullin ;;
		esac
		case $user_yn in
		?*)	case $def in
			-)	;;
			*)	case $note in
				?*)	case $user_yn in
					*$nl*)	user_yn="/* $note */$nl$user_yn" ;;
					*)	user_yn="$user_yn	/* $note */" ;;
					esac
					;;
				esac
				;;
			esac
			copy - "$user_yn"
			;;
		esac
		case $ifelse:$result in
		TEST:SUCCESS)	ifelse=KEEP ;;
		TEST:*)		ifelse=SKIP ;;
		esac
		case $group:$result in
		:*|*:SUCCESS)	break ;;
		esac
		set '' $groups '' "$@"
		shift
		case $1 in
		'')	shift; break ;;
		esac
		shift

		# set up and try the next group

		hdr=$com_hdr
		lib=$com_lib
		mac=$com_mac
		opt=$com_opt
		pth=$com_pth
		test=$com_test
		cc="$occ $includes"
		group=
		groups=
		while	:
		do	case $1 in
			'')	shift; break ;;
			esac
			case $1 in
			*[\"\'\(\)\{\}\ \	]*)
				case $op in
				pth)	pth="$pth $1"
					;;
				*)	case $test in
					'')	test=$1 ;;
					*)	test="$test $1" ;;
					esac
					;;
				esac
				;;
			-)	group=$group$1
				groups="$groups $1"
				;;
			-l*)	case $group in
				-*)	groups="$groups $1" ;;
				*)	lib="$lib $1" ;;
				esac
				;;
			+l*)	case $shell in
				bsh)	x=`echo X$1 | sed 's/X+/-/'` ;;
				*)	eval 'x=-${1#+}' ;;
				esac
				case $group in
				-*)	groups="$groups $x" ;;
				*)	lib="$lib $x" ;;
				esac
				;;
			-*|+*)	case $group in
				-*)	groups="$groups $1"
					;;
				*)	case $op in
					run)	opt="$opt $1"
						;;
					*)	case $1 in
						-D*)	mac="$mac $1" ;;
						*)	cc="$cc $1" ;;
						esac
						;;
					esac
					;;
				esac
				;;
			*.[aAxX]|*.[dD][lL][lL]|*.[lL][iI][bB])
				case $group in
				-*)	groups="$groups $1" ;;
				*)	lib="$lib $1" ;;
				esac
				;;
			*[.\\/]*)
				case $group in
				-*)	groups="$groups $1"
					;;
				*)	case $op in
					pth)	pth="$pth $1" ;;
					*)	hdr="$hdr $1" ;;
					esac
					;;
				esac
				;;
			*)	case $group in
				-*)	groups="$groups $1"
					;;
				*)	case $op in
					pth)	pth="$pth $1"
						;;
					*)	case $test in
						'')	test=$1 ;;
						*)	test="$test $1" ;;
						esac
						;;
					esac
					;;
				esac
				;;
			esac
			shift
		done
	done
done
