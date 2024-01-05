#! /bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
#
#
# Generates the list of source files that would get brought over with the
# specified subtree as a result of inc.flg and req.flg files.  If no subtree
# is named, then the current directory is assumed.
#
# Based loosely on ON's version of Teamware's def.dir.flp.
#

ONBLDDIR=$(dirname $(whence $0))

PATH=/usr/bin:${BUILD_TOOLS:-/opt}/teamware/bin:$ONBLDDIR
export PATH
PROG=$(basename $0)

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which will screw up consumers of incflg()
# (and perhaps other things as well); unset it.
#
unset CDPATH

#
# Print the usage message and exit with an error.
#
usage()
{
	echo "usage: $PROG [-r] [<dir>]" > /dev/stderr
	exit 1
}

#
# Print the provided failure message and exit with an error.
#
fail()
{
	echo $PROG: $@ > /dev/stderr
	exit 1
}

# Find the files matching the pattern specified by the first argument in the
# directories named by the remaining arguments.  Unlike def.dir.flp, print
# the name of the source file since we want to make a list of source files,
# not SCCS files.
#
find_files()
{
	pat=$1
	shift

	if [[ "$SCM_MODE" == "teamware" ]]; then
		for dir; do
			if [[ -d $CODEMGR_WS/$dir ]]; then
				cd $CODEMGR_WS
				find $dir -name "$pat" | \
					sed -n s:/SCCS/s.:/:p | prpath
				cd - > /dev/null
			fi
		done
	elif [[ "$SCM_MODE" == "mercurial" || "$SCM_MODE" == "git" ]]; then
		dirs=""
		for dir; do
			if [[ -d $CODEMGR_WS/$dir ]]; then
				dirs="$dirs|${dir%/}"
			fi
		done

		# Remove leading pipe before it can confuse egrep
		dirs=${dirs#\|}
		echo "$FILELIST" | egrep "^($dirs)/.*/${pat#s.}\$" | prpath
	fi
}

#
# Echo the filename if it exists in the workspace.
#
echo_file()
{
	[ -f $CODEMGR_WS/$1 ] && echo $1 | prpath
}

#
# Source the named script, specified as either a full path or a path relative
# to $CODEMGR_WS.  Although def.dir.flp allows for situations in which the
# script is actually executed (rather than sourced), this feature has never
# been used in ON, since it precludes use of echo_file() and find_files().
#
exec_file()
{
	if [[ "${1##/}" == "$1" ]]; then
		. $CODEMGR_WS/$1
	else
		. $1
	fi
}

#
# Iterate up through all directories below the named directory, and
# execute any inc.flg's that may exist.
#
incflg()
{
	cd $1
	for i in * .*; do
		case $i in
		'*'|.|..)
			;;
		inc.flg)
			exec_file $1/$i
			;;
		*)
			if [[ -d $i && ! -h $i ]]; then
				incflg $1/$i
				cd $1
			fi
			;;
		esac
	done
}

#
# Convert the absolute pathnames named on input to relative pathnames (if
# necessary) and print them.
#
prpath()
{
	#
	# $CURTREE may be a subdirectory of $CODEMGR_WS, or it
	# may be the root of $CODEMGR_WS.  We want to strip it
	# and end up with a relative path in either case, so the
	# ?(/) pattern is important.  If we don't do that, the
	# dots/tree loop will go on forever.
	#
	reltree=${CURTREE##$CODEMGR_WS?(/)}

	while read srcfile; do
		if [[ "$RELPATHS" != y ]]; then
			echo $srcfile
			continue
		fi

		dots=
		tree=$reltree
		while [[ "${srcfile##$tree}" == "$srcfile" ]]; do
			dots=../$dots
			tree=$(dirname $tree)
			[ "$tree" = "." ] && break
		done
		echo ${dots}${srcfile##$tree/}
	done
}

which_scm | read SCM_MODE CODEMGR_WS || exit 1

if [[ $SCM_MODE == "unknown" ]]; then
	fail "Unable to determine SCM type currently in use."
elif [[ $SCM_MODE == "mercurial" ]]; then
	FILELIST=$(hg manifest)
elif [[ $SCM_MODE == "git" ]]; then
	FILELIST=$(cd $(dirname $(git rev-parse --git-dir)) && git ls-files)
elif [[ $SCM_MODE != "teamware" ]]; then
	fail "Unsupported SCM in use: $SCM_MODE"
fi

while getopts r flag; do
	case $flag in
	r)
		RELPATHS=y
		;;
	\?)
		usage
		;;
	esac
done

shift $((OPTIND - 1))

(( $# > 1 )) && usage

CURTREE=$(/bin/pwd)

#
# Determine the subtree being examined.
#
if (( $# == 0 )); then
	SUBTREE=$CURTREE
elif [[ -d $1 ]]; then
	SUBTREE=$1
elif [[ -d "$CODEMGR_WS/$1" ]]; then
	SUBTREE="$CODEMGR_WS/$1"
else
	fail "neither \$CODEMGR_WS/$1 nor $1 exists as a directory"
fi

#
# Get the canonical path to the subtree.
#
cd $SUBTREE
SUBTREE=$(/bin/pwd)

#
# Get the canonical path to the current directory.
#
cd $CURTREE
CURTREE=$(/bin/pwd)

#
# Get the canonical path to the workspace.
#
cd $CODEMGR_WS
CODEMGR_WS=$(/bin/pwd)

if [[ "${SUBTREE##$CODEMGR_WS}" == "$SUBTREE" ]]; then
	fail "$SUBTREE is not a subtree of \$CODEMGR_WS"
fi

if [[ "${CURTREE##$CODEMGR_WS}" == "$CURTREE" ]]; then
	fail "$CURTREE is not a subtree of \$CODEMGR_WS"
fi

#
# Find and execute all inc.flg's below our subtree.
#
incflg $SUBTREE

#
# Find and execute all req.flg's at or above our subtree.
#
TREE=$SUBTREE
while [[ $TREE != $CODEMGR_WS ]]; do
	[[ -f $TREE/req.flg ]] && exec_file $TREE/req.flg
	TREE=$(dirname $TREE)
done

exit 0
