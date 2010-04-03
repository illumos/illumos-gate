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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# simplefileattributetree1 - build a simple file tree (including file attributes)
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


function add_file_to_tree
{
	typeset treename=$1
	typeset filename=$2
	nameref destnodename=$3
	integer i
	typeset nodepath # full name of compound variable
	typeset -a pe # path elements

	# first built an array containing the names of each path element
	# (e.g. "foo/var/baz"" results in an array containing "( 'foo' 'bar' 'baz' )")
	typeset IFS='/'
	pe+=( ${filename} )
	
	[[ ${pe[0]} == '' ]] && pe[0]='/'

	# walk path described via the "pe" array and build nodes if
	# there aren't any nodes yet
	nodepath="${treename}"
	for (( i=0 ; i < (${#pe[@]}-1) ; i++ )) ; do
		nameref x="${nodepath}"

		# [[ -v ]] does not work for arrays because [[ -v ar ]]
		# is equal to [[ -v ar[0] ]]. In this case we can
		# use the output of typeset +p x.nodes
		[[ "${ typeset +p x.nodes ; }" == "" ]] && compound -A x.nodes
	
		nodepath+=".nodes[${pe[i]}]"
	done
	
	# insert element
	nameref node="${nodepath}"
	[[ "${ typeset +p node.elements ; }" == "" ]] && compound -A node.elements
	node.elements[${pe[i]}]=(
		filepath="${filename}"
	)
	
	destnodename="${!node}.elements[${pe[i]}]"
	
	return 0
}

function parse_findls
{
	nameref out=$1
	typeset str="$2"
	
	# find -ls on Solaris uses the following output format by default:
	#604302    3 -rw-r--r--   1 test001  users        2678 May  9 00:46 ./httpsresdump

	integer out.inodenum="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\1}"
	integer out.kbblocks="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\2}"
	typeset out.mode="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\3}"
	integer out.numlinks="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\4}"
	compound out.owner=(
		typeset user="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\5}"
		typeset group="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\6}"
	)
	integer out.filesize="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\7}"
	typeset out.date="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\8}"
	typeset out.filepath="${str/~(Elr)[[:space:]]*([[:digit:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]-]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:alnum:]]+)[[:space:]]+([[:digit:]]+)[[:space:]]+([[:alpha:]]*[[:space:]]+[[:digit:]]*[[:space:]]+[[:digit:]:]+)[[:space:]]+(.+)/\9}"

	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${simplefileattributetree1_usage}" OPT '-?'
	exit 2
}

# main
builtin basename
builtin dirname

set -o noglob
set -o nounset

# tree base
compound filetree

# benchmark data
compound bench=(
	float start
	float stop
)

compound appconfig=(
	typeset do_benchmarking=false
	compound do_record=(
		typeset content=false
		typeset filetype=false
	)
)


integer i

typeset progname="${ basename "${0}" ; }"

typeset -r simplefileattributetree1_usage=$'+
[-?\n@(#)\$Id: simplefileattributetree1 (Roland Mainz) 2010-03-27 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?simplefileattributetree1 - generate compound variable tree which contains file names and their attributes]
[+DESCRIPTION?\bsimplefileattributetree1\b is a simple variable tree 
	demo which builds a compound variable tree based on the output
	of /usr/xpg4/bin/file which contains the file name, the file attributes
	and optionally file type and content]
[b:benchmark?Print time needed to generate the tree.]
[c:includecontent?Include the file\'s content in the tree, split into 1kb blocks.]
[t:includefiletype?Include the file type (output of /usr/xpg4/bin/file).]

path

[+SEE ALSO?\bksh93\b(1), \bfile\b(1), \bfind\b(1)]
'

while getopts -a "${progname}" "${simplefileattributetree1_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		b)	appconfig.do_benchmarking="true"	;;
		+b)	appconfig.do_benchmarking="false"	;;
		c)	appconfig.do_record.content="true"	;;
		+c)	appconfig.do_record.content="false"	;;
		t)	appconfig.do_record.filetype="true"	;;
		+t)	appconfig.do_record.filetype="false"	;;
		*)	usage ;;
	esac
done
shift $((OPTIND-1))


# argument prechecks
if (( $# == 0 )) ; then
	print -u2 -f "%s: Missing <path> argument.\n" "${progname}"
	exit 1
fi


print -u2 -f "# reading file names...\n"
while (( $# > 0 )) ; do
	# "ulimit -c 0" use used to force ksh93 to use a seperate process for subshells,
	# this is used to work around a bug with LC_ALL changes bleeding through subshells
	IFS=$'\n' ; typeset -a findls_lines=( $(ulimit -c 0 ; LC_ALL=C find "$1" -type f -ls) ) ; IFS=$' \t\n'
	shift
done


print -u2 -f "# building tree...\n"

${appconfig.do_benchmarking} && (( bench.start=SECONDS ))

for (( i=0 ; i < ${#findls_lines[@]} ; i++ )) ; do
	compound parseddata
	typeset treenodename
	
	# parse "find -ls" output
	parse_findls parseddata "${findls_lines[i]}"
	
	# add node to tree and return it's absolute name in "treenodename"
	add_file_to_tree filetree "${parseddata.filepath}" treenodename
	
	# merge parsed "find -ls" output into tree node
	nameref treenode="${treenodename}"
	treenode+=parseddata
	
	# extras (calculated from the existing values in "parseddata")
	typeset treenode.dirname="${ dirname "${treenode.filepath}" ; }"
	typeset treenode.basename="${ basename "${treenode.filepath}" ; }"
	
	if ${appconfig.do_record.filetype} ; then
		# Using /usr/(xpg4/)*/bin/file requires a |fork()|+|exec()| which makes the script a few hundred times slower... ;-(
		typeset treenode.filetype="$(file "${treenode.filepath}")"
	fi
	
	if ${appconfig.do_record.content} ; then
		if [[ -r "${treenode.filepath}" ]] ; then
			# We use an array of compound variables here to support
			# files with holes (and later alternative streams, too)
			compound -a treenode.content
			integer cl=0
			while \
				{
					treenode.content[${cl}]=(
						typeset type="data" # (todo: "add support for "holes" (sparse files))
						typeset -b bin
					)
					read -n1024 treenode.content[${cl}].bin
				} ; do
				(( cl++ ))
			done < "${treenode.filepath}"
			unset treenode.content[${cl}]

			typeset -A treenode.hashsum=(
				[md5]="$(sum -x md5 < "${treenode.filepath}")"
				[sha512]="$(sum -x sha512 < "${treenode.filepath}")"
			)
		
			# we do this for internal debugging only
			if [[ "${ {
					integer j
					for (( j=0 ; j < ${#treenode.content[@]} ; j++ )) ; do
						printf "%B" treenode.content[$j].bin
					done
				} | sum -x sha512 ; }" != "${treenode.hashsum[sha512]}" ]] ; then
				# this should never happen...
				print -u2 -f "fatal hash mismatch for %s\n" "${treenode.filepath}"
				unset treenode.content treenode.hashsum
			fi
		fi
	fi
done

${appconfig.do_benchmarking} && (( bench.stop=SECONDS ))


if ${appconfig.do_benchmarking} ; then
	# print benchmark data
	print -u2 -f "# time used: %f\n" $((bench.stop - bench.start))
fi

# print variable tree
print -v filetree

exit 0
# EOF.
