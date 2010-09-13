#!/sbin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/
# This program changes all occurences of the SVR2 getopt invocation line
# to use the SVR3 version of getopt.
# Sedfunc is used to handle arguments with single quotes.
# If -b option is given, getoptcvt will create script that will usually work
# in releases previous to 3.0.
bflag=
while getopts b c
do
	case $c in
	b)  bflag=1;;
	\?) echo "getoptcvt [-b] file"
	    exit 2;;
	esac
done
shift `expr $OPTIND - 1`
if [ "$bflag" = 1 ]
then
	ed <<'!' - $1
1,$s/set[ 	][ 	]*--[ 	][ 	]*`getopt[ 	][ 	]*\(.*\)[ 	][ 	]*.*`/{\
if [ "$OPTIND" != 1 ]\
then\
	set -- `getopt \1 $*`\
else\
sedfunc() \
{\
echo "$1" | sed "s\/'\/'\\\\\\\\''\/g"\
}\
exitcode_=0\
while getopts \1 c_\
do\
	case $c_ in\
	\\?)\
		exitcode_=1\
		break;;\
	*)	if [ "$OPTARG" ]\
		then\
			optarg_=`sedfunc "$OPTARG"`\
			arg_="$arg_ '-$c_' '$optarg_'"\
		else\
			arg_="$arg_ '-$c_'"\
		fi;;\
	esac\
done\
shift `expr $OPTIND - 1`\
arg_="$arg_ '--'"\
for i_ in "$@"\
do\
	optarg_=`sedfunc "$i_"`\
	arg_="$arg_ '$optarg_'"\
done\
eval set -- "$arg_"\
test  $exitcode_ = 0\
fi ;}/
1,$p
Q
!
else
	ed <<'!' - $1
1,$s/set[ 	][ 	]*--[ 	][ 	]*`getopt[ 	][ 	]*\(.*\)[ 	][ 	]*.*`/{\
sedfunc()\
{\
echo "$1" | sed "s\/'\/'\\\\\\\\''\/g"\
}\
exitcode_=0\
while getopts \1 c_\
do\
	case $c_ in\
	\\?)\
		exitcode_=1\
		break;;\
	*)	if [ "$OPTARG" ]\
		then\
			optarg_=`sedfunc "$OPTARG"`\
			arg_="$arg_ -$c_ '$optarg_'"\
		else\
			arg_="$arg_ -$c_"\
		fi;;\
	esac\
done\
shift `expr $OPTIND - 1`\
arg_="$arg_ --"\
for i_ in "$@"\
do\
	optarg_=`sedfunc "$i_"`\
	arg_="$arg_ '$optarg_'"\
done\
eval set -- "$arg_"\
test  $exitcode_ = 0 ;}/
1,$p
Q
!
fi
