#!/usr/bin/ksh93

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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

# Solaris needs /usr/xpg6/bin:/usr/xpg4/bin because the tools in /usr/bin are not POSIX-conformant
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/bin:/usr/bin

# Make sure all math stuff runs in the "C" locale to avoid problems
# with alternative # radix point representations (e.g. ',' instead of
# '.' in de_DE.*-locales). This needs to be set _before_ any
# floating-point constants are defined in this script).
if [[ "${LC_ALL}" != "" ]] ; then
    export \
        LC_MONETARY="${LC_ALL}" \
        LC_MESSAGES="${LC_ALL}" \
        LC_COLLATE="${LC_ALL}" \
        LC_CTYPE="${LC_ALL}"
        unset LC_ALL
fi
export LC_NUMERIC=C

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}


function do_directory
{
	nameref tree=$1
	typeset basedir="$2"
	
	typeset basename
	typeset dirname
	typeset i
	typeset dummy
	
	typeset -C -A tree.files
	typeset -C -A tree.dirs

	find "${basedir}"/* -prune 2>/dev/null | while read i ; do
		dirname="$(dirname "$i")"
		basename="$(basename "$i")"
		
		# define "node"
		if [[ -d "$i" ]] ; then
			typeset -C tree.dirs["${basename}"]
			nameref node=tree.dirs["${basename}"]
			typeset -C node.flags
			node.flags.dir="true"
			node.flags.file="false"
		else
			typeset -C tree.files["${basename}"]
			nameref node=tree.files["${basename}"]
			typeset -C node.flags
			
			node.flags.dir="false"
			node.flags.file="true"
		fi

		# basic attributes
		typeset -C node.paths=(
			dirname="${dirname}"
			basename="${basename}"
			path="${i}"
		)
		
		nameref nflags=node.flags
		[[ -r "$i" ]] && nflags.readable="true"   || nflags.readable="false"
		[[ -w "$i" ]] && nflags.writeable="true"  || nflags.writeable="false"
		[[ -x "$i" ]] && nflags.executable="true" || nflags.executable="false"

		[[ -b "$i" ]] && nflags.blockdevice="true"     || nflags.blockdevice="false"
		[[ -c "$i" ]] && nflags.characterdevice="true" || nflags.characterdevice="false"
		[[ -S "$i" ]] && nflags.socket="true"          || nflags.socket="false"

		[[ -L "$i" ]] && nflags.symlink="true" || nflags.symlink="false"

		integer node.size
		integer node.links
		typeset -C node.owner
		( [[ -x /usr/bin/runat ]] && ls -@ade "$i" || ls -lade "$i" ) |
		IFS=' ' read \
			node.mask \
			node.links \
			node.owner.uid \
			node.owner.gid \
			node.size \
			dummy
		
		typeset -C node.extended_attributes
		if [[ ${node.mask} == ~(Er)@ ]] ; then
			node.extended_attributes.hasattrs="true"
			typeset -a attrlist=(
				$( runat "$i" "ls -1" )
			)
		else
			node.extended_attributes.hasattrs="false"
		fi
		
		if ${nflags.readable} ; then
			# note that /usr/xpg4/bin/file does not use $'\t' as seperator - we
			# have to use ':' instead.
			file -h "$i" | IFS=' ' read dummy node.filetype
		fi

		if ${nflags.dir} ; then
			do_directory "${!node}" "$i"
		fi
	done
	
	# remove empty lists
	(( ${#tree.files[@]} == 0 )) && unset tree.files
	(( ${#tree.dirs[@]} == 0 ))  && unset tree.dirs

	return 0
}


function pathtovartree
{
	nameref tree=$1
	typeset basedir="$2"
	
	do_directory tree "${basedir}"

	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${filetree1_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin dirname
builtin date
builtin uname

typeset progname="${ basename "${0}" ; }"

typeset -r filetree1_usage=$'+
[-?\n@(#)\$Id: filetree1 (Roland Mainz) 2009-05-06 \$\n]
[-author?Roland Mainz <roland.mainz@sun.com>]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?filetree1 - file tree demo]
[+DESCRIPTION?\bfiletree1\b is a small ksh93 compound variable demo
	which accepts a directory name as input, and then builds tree
	nodes for all files+directories and stores all file attributes
	in these notes and then outputs the tree in the format
	specified by viewmode (either "list", "namelist", "tree" or "compacttree")..]

viewmode dirs

[+SEE ALSO?\bksh93\b(1), \bfile\b(1)]
'

while getopts -a "${progname}" "${filetree1_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

typeset viewmode="$1"
shift

if [[ "${viewmode}" != ~(Elr)(list|namelist|tree|compacttree) ]] ; then
	fatal_error $"Invalid view mode \"${viewmode}\"."
fi

typeset -C myfiletree

while (( $# > 0 )) ; do
	print -u2 -f "# Scanning %s ...\n" "${1}"
	pathtovartree myfiletree "${1}"
	shift
done
print -u2 $"#parsing completed."

case "${viewmode}" in
	list)
		set | egrep "^myfiletree\[" | fgrep -v ']=$'
		;;
	namelist)
		typeset + | egrep "^myfiletree\["
		;;
	tree)
		print -v myfiletree
		;;
	compacttree)
		print -C myfiletree
		;;
	*)
		fatal_error $"Invalid view mode \"${viewmode}\"."
		;;
esac

print -u2 $"#done."

exit 0
# EOF.
