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
: cross compiler a.out execution

command=crossexec

tmp=/tmp/cross$$

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	ARGV0="-a $command"
	USAGE=$'
[-?
@(#)$Id: crossexec (AT&T Labs Research) 2004-01-04 $
]
'$USAGE_LICENSE$'
[+NAME?crossexec - cross compiler a.out execution]
[+DESCRIPTION?\bcrossexec\b runs a cross-compiled \acommand\a in an environment
	that supports a cross-compilation architecture different from the
	current host. The cross environment is determined by \acrosstype\a,
	usually a host type name produced by \bpackage\b(1). \acrosstype\a
	is used to find an entry in \b$HOME/.crossexec\b that specifies
	the cross compiler host and access details.]
[+?The exit status of \bcrossexec\b is the exit status of \acommand\a.]
[+CROSS ENVIRONMENT FILE?\b$HOME/.crossexec\b contains one line for each
	supported \acrosstype\a. Each line contains 5 tab separated fields.
	Field default values are specified as \b-\b. The fields are:]{
	[+crosstype?The host type produced by \bpackage\b(1).]
	[+host?The host name.]
	[+user?The user name on \ahost\a. The default is the current user.]
	[+dir?The directory to copy \acommand\a and execute it. The default
		is the \auser\a \b$HOME\b on \ahost\a.]
	[+shell?The command used to get shell access to \ahost\a. Currently
		only \brsh\b and \bssh\b are supported.]
	[+copy?The command used to copy \acommand\a to \ahost\a. Currently
		only \brcp\b and \bscp\b are supported.]
}
[n:show?Show the underlying commands but do not execute.]

crosstype command [ option ... ] [ file ... ]

[+SEE ALSO?\brcp\b(1), \brsh\b(1), \bscp\b(1), \bssh\b(1)]
'
	;;
*)	ARGV0=""
	USAGE="crosstype command [ option ... ] [ file ... ]"
	;;
esac

usage()
{
	OPTIND=0
	getopts $ARGV0 "$USAGE" OPT '-?'
	exit 2
}

exec=

# get the options and operands

while	getopts $ARGV0 "$USAGE" OPT
do	case $OPT in
	n)	exec=echo ;;
	*)	usage ;;
	esac
done
shift $OPTIND-1
case $# in
[01])	usage ;;
esac

type=$1
shift
cmd=$1
shift

# get the host info

info=$HOME/.$command
if	test ! -r $info
then	echo "$command: $info: not found" >&2
	exit 1
fi
ifs=${IFS-'
	 '}
while	:
do	IFS='	'
	read hosttype hostname usr dir sh cp
	code=$?
	IFS=$ifs
	case $code in
	0)	;;
	*)	echo "$command: $type: unknown cross compiler host type" >&2
		exit 1
		;;
	esac
	case $hosttype in
	$type)	break ;;
	esac
done < $info

# fill in the defaults

case $usr in
-)	cpu= shu= ;;
*)	cpu=${usr}@ shu="-l $usr" ;;
esac
case $dir in
-)	dir= ;;
esac
case $sh in
''|-)	sh=ssh ;;
esac
case $cp in
''|-)	cp=scp ;;
scp)	cp="$cp -q" ;;
esac

trap "rm -f $tmp" 0 1 2 3 15
$exec $cp $cmd $cpu$hostname:$dir </dev/null || exit 1
cmd=./${cmd##*/}
$exec $sh $shu $hostname "cd $dir; LD_LIBRARY_PATH=: $cmd $@ </dev/null 2>/dev/null; code=\$?; rm -f $cmd; echo $command: exit \$code >&2" </dev/null 2>$tmp
exit `sed -e '/^'$command': exit [0-9][0-9]*$/!d' -e 's/.* //' $tmp`
