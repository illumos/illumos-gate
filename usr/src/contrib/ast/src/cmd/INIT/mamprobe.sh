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
### this script contains archaic constructs that work with all sh variants ###
# mamprobe - generate MAM cc probe info
# Glenn Fowler <gsf@research.att.com>

case $-:$BASH_VERSION in
*x*:[0123456789]*)	: bash set -x is broken :; set +ex ;;
esac

command=mamprobe

# check the options

opt=

case `(getopts '[-][123:xyz]' opt --xyz; echo 0$opt) 2>/dev/null` in
0123)	USAGE=$'
[-?
@(#)$Id: mamprobe (AT&T Labs Research) 2011-02-11 $
]
[+NAME?mamprobe - generate MAM cc probe info]
[+DESCRIPTION?\bmamprobe\b generates MAM (make abstract machine) \bcc\b(1)
	probe information for use by \bmamake\b(1). \acc-path\a is the
	absolute path of the probed compiler and \ainfo-file\a is where
	the information is placed. \ainfo-file\a is usually
	\b$INSTALLROOT/lib/probe/C/mam/\b\ahash\a, where \ahash\a is a hash
	of \acc-path\a. Any \ainfo-file\a directories are created if needed.
	If \ainfo-file\a is \b-\b then the probe information is written to
	the standard output.]
[+?\bmamprobe\b and \bmamake\b are used in the bootstrap phase of
	\bpackage\b(1) installation before \bnmake\b(1) is built. The
	probed variable names are the \bnmake\b(1) names with a \bmam_\b
	prefix, \bCC\b converted to \bcc\b,  and \b.\b converted to \b_\b.
	Additional variables are:]{
		[+_hosttype_?the \bpackage\b(1) host type]
		[+mam_cc_L?\b-L\b\adir\a supported]
		[+STDCAT?command to execute for \bcat\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
		[+STDCHMOD?command to execute for \bchmod\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
		[+STDCMP?command to execute for \bcmp\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
		[+STDCP?command to execute for \bcp\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
		[+STDED?command to execute for \bed\b(1) or \bex\b(1)]
		[+STDEDFLAGS?flags for \bSTDED\b]
		[+STDLN?command to execute for \bln\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
		[+STDMV?command to execute for \bmv\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
		[+STDRM?command to execute for \brm\b(1); prefixed by
			\bexecrate\b(1) on \b.exe\b challenged systems]
}
[d:debug?Enable probe script debug trace.]

info-file cc-path

[+SEE ALSO?\bexecrate\b(1), \bpackage\b(1), \bmamake\b(1), \bnmake\b(1),
	\bprobe\b(1)]
'
	while	getopts -a "$command" "$USAGE" OPT
	do	case $OPT in
		d)	opt=-d ;;
		esac
	done
	shift `expr $OPTIND - 1`
	;;
*)	while	:
	do	case $# in
		0)	break ;;
		esac
		case $1 in
		--)	shift
			break
			;;
		-)	break
			;;
		-d)	opt=-d
			;;
		-*)	echo $command: $1: unknown option >&2
			;;
		*)	break
			;;
		esac
		set ''
		break
	done
	;;
esac

# check the args

case $1 in
-)	;;
/*)	;;
*)	set '' ;;
esac
case $2 in
/*)	;;
*)	set '' ;;
esac
case $# in
0|1)	echo "Usage: $command info-file cc-path" >&2; exit 2 ;;
esac
info=$1
shift
cc=$*

# find the make probe script

ifs=${IFS-'
	 '}
IFS=:
set $PATH
IFS=$ifs
script=lib/probe/C/make/probe
while	:
do	case $# in
	0)	echo "$0: ../$script: probe script not found on PATH" >&2
		exit 1
		;;
	esac
	case $1 in
	'')	continue ;;
	esac
	makeprobe=`echo $1 | sed 's,[^/]*$,'$script,`
	if	test -x $makeprobe
	then	break
	fi
	shift
done

# create the info dir if necessary

case $info in
/*)	i=X$info
	ifs=${IFS-'
	 '}
	IFS=/
	set $i
	IFS=$ifs
	while	:
	do	i=$1
		shift
		case $i in
		X)	break ;;
		esac
	done
	case $info in
	//*)	path=/ ;;
	*)	path= ;;
	esac
	while	:
	do	case $# in
		0|1)	break ;;
		esac
		comp=$1
		shift
		case $comp in
		'')	continue ;;
		esac
		path=$path/$comp
		if	test ! -d $path
		then	mkdir $path || exit
		fi
	done
	;;
esac

# generate info in a tmp file and rename when finished

case $info in
-)	;;
*)	tmp=/tmp/mam$$
	trap "exec >/dev/null; rm -f $tmp" 0 1 2 3 15
	exec > $tmp
	echo "probing C language processor $cc for mam information" >&2
	;;
esac

echo "note generated by $0 for $cc"

(
	set '' $opt $cc
	shift
	. $makeprobe "$@"

	case " $CC_DIALECT " in
	*" -L "*)	echo "CC.L = 1" ;;
	esac

) | sed \
	-e '/^CC\./!d' \
	-e 's/^CC./setv mam_cc_/' \
	-e 's/^\([^=.]*\)\./\1_/' \
	-e 's/^\([^=.]*\)\./\1_/' \
	-e 's/ =//' \
	-e 's/\$("\([^"]*\)")/\1/g' \
	-e 's/\$(\([^)]*\))/${\1}/g' \
	-e 's/\${CC\./${mam_cc_}/g'

echo 'setv _hosttype_ ${mam_cc_HOSTTYPE}'

# STD* are standard commands/flags with possible execrate(1)

if	(
ed <<!
q
!
) < /dev/null > /dev/null 2>&1
then	STDED=ed
else	STDED=ex
fi
STDEDFLAGS=-
set STDCAT cat STDCHMOD chmod STDCMP cmp STDCP cp STDLN ln STDMV mv STDRM rm
while	:
do	case $# in
	0|1)	break ;;
	esac
	p=$2
	for d in /bin /usr/bin /usr/sbin
	do	if	test -x $d/$p
		then	p=$d/$p
			break
		fi
	done
	eval $1=\$p
	shift
	shift
done
if	execrate
then	for n in STDCAT STDCHMOD STDCMP STDCP STDLN STDMV STDRM
	do	eval $n=\"execrate \$$n\"
	done
fi
for n in STDCAT STDCHMOD STDCMP STDCP STDED STDEDFLAGS STDLN STDMV STDRM
do	eval echo setv \$n \$$n
done

# all done

case $info in
-)	;;
*)	exec >/dev/null
	test -f $info && rm -f $info
	cp $tmp $info
	chmod -w $info
	;;
esac
