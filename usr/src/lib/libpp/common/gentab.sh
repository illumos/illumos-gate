########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1986-2009 AT&T Intellectual Property          #
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
#                 Glenn Fowler <gsf@research.att.com>                  #
#                                                                      #
########################################################################
:
# Glenn Fowler
# AT&T Bell Laboratories
#
# @(#)gentab (gsf@research.att.com) 07/17/94
#
# C table generator
#
#	%flags [ prefix=<prefix> ] [ index=<index> ] [ init=<init> ]
#
#	%keyword <name> [ prefix=<prefix> ] [ index=<index> ] [ init=<init> ] [ first=<id> ] [ last=<id> ]
#
#	%sequence [ prefix=<prefix> ] [ index=<index> ] [ init=<init> ]
#

case `(typeset -u s=a n=0; ((n=n+1)); print $s$n) 2>/dev/null` in
A1)	shell=ksh
	typeset -u ID
	typeset -i counter err_line
	;;
*)	shell=bsh
	;;
esac
command=$0
counter=0
define=1
err_line=0
type=""
index=""
first=""
last=""
table=1
while	:
do	case $1 in
	-d)	table=0 ;;
	-t)	define=0 ;;
	*)	break ;;
	esac
	shift
done
case $1 in
"")	err_file=""
	;;
*)	exec <$1
	err_file="\"$1\", "
	;;
esac
while	read line
do	case $shell in
	ksh)	((err_line=err_line+1)) ;;
	*)	err_line=`expr $err_line + 1` ;;
	esac
	set '' $line
	shift
	case $1 in
	[#]*)	echo "/*"
		while	:
		do	case $1 in
			[#]*)	shift
				echo " * $*"
				read line
				set '' $line
				shift
				;;
			*)	break
				;;
			esac
		done
		echo " */"
		echo
		;;
	esac
	eval set '""' $line
	shift
	case $1 in
	"")	;;
	%flags|%keywords|%sequence)
		case $define:$last in
		1:?*)	case $shell in
			ksh)	((n=counter-1)) ;;
			*)	n=`expr $counter - 1` ;;
			esac
			echo "#define $prefix$last	$n"
			;;
		esac
		case $type in
		%flags|%sequence)
			if	test $define = 1
			then	echo
			fi
			;;
		%keywords)
			if	test $table = 1
			then	echo "	0,	0"
				echo "};"
				echo
			elif	test $define = 1
			then	echo
			fi
			;;
		esac
		case $index in
		?*)	eval $index=$counter ;;
		esac
		type=$1
		shift
		name=""
		prefix=""
		index=""
		init=""
		first=""
		last=""
		case $type in
		%keywords)
			case $1 in
			"")	echo "$command: ${err_file}line $err_line: $type table name omitted" >&2
				exit 1
				;;
			esac
			name=$1
			shift
			if	test $table = 1
			then	echo "$name"'[] ='
				echo "{"
			fi
			;;
		esac
		eval "$@"
		case $init in
		"")	case $type in
			%flags|%sequence)
				init=0
				;;
			*)	init=1
				;;
			esac
			;;
		esac
		case $index in
		"")	counter=$init
			;;
		*)	eval value=\$$index
			case $value in
			"")		counter=$init ;;
			[0123456789]*)	counter=$value ;;
			esac
			;;
		esac
		case $define:$first in
		1:?*)	echo "#define $prefix$first	$counter" ;;
		esac
		;;
	%*)	echo "$command: ${err_file}line $err_line: $1: unknown keyword" >&2
		exit 1
		;;
	*)	while	:
		do	case $1 in
			"")	break
				;;
			*)	case $shell in
				ksh)	ID=${1#[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_]} ;;
				*)	ID=`echo $1 | tr abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ | sed 's/^[^ABCDEFGHIJKLMNOPQRSTUVWXYZ_]//'` ;;
				esac
				case $type in
				%flags)	if	test $define = 1
					then	case $counter in
						32) echo "$command: ${err_file}line $err_line: warning: $1: too many flag bits" >&2 ;;
						1[56789]|[23][0123456789]) long=L ;;
						*) long= ;;
						esac
						echo "#define $prefix$ID	(1$long<<$counter)"
					fi
					;;
				%keywords)
					if	test $define = 1
					then	echo "#define $prefix$ID	$counter"
					fi
					if	test $table = 1
					then	echo "	\"$1\",	$prefix$ID,"
					fi
					;;
				%sequence)
					if	test $define = 1
					then	echo "#define $prefix$ID	$counter"
					fi
					;;
				esac
				case $shell in
				ksh)	((counter=counter+1)) ;;
				*)	counter=`expr $counter + 1` ;;
				esac
				shift
				;;
			esac
		done
		;;
	esac
done
case $define:$last in
1:?*)	case $shell in
	ksh)	((n=counter-1)) ;;
	*)	n=`expr $counter - 1` ;;
	esac
	echo "#define $prefix$last	$n"
	;;
esac
case $type in
%keywords)
	if	test $table = 1
	then	echo "	0,	0"
		echo "};"
	fi
	;;
esac
exit 0
