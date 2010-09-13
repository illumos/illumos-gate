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


function svcproptovartree
{
	nameref tree=$1

	typeset name
	typeset servicename
	typeset propname

	typeset datatype

	typeset -a fields
	integer num_fields
	integer i

	while IFS=' ' read -A fields ; do
		num_fields=${#fields[*]}

		name="${fields[0]}"
		datatype="${fields[1]}"
		# parse service/property name
		servicename="${name%~(Er):properties/.*}"
		servicename="${servicename/~(El)svc:\//}" # strip "svc:/"
		propname="${name#~(El).*:properties/}"

		[[ "${ typeset +p "tree[${servicename}].properties" ; }" == "" ]] && compound -A tree[${servicename}].properties
	
		nameref node=tree[${servicename}].properties[${propname}]

		node=(
			typeset datatype="${datatype}"
			typeset valuelist="true"
			typeset -a values
		)
	
		for (( i=2 ; i < num_fields ; i++ )) ; do
			node.values+=( "${fields[i]}" )
		done
	done

	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${svcproptree1_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin date
builtin uname

typeset progname="${ basename "${0}" ; }"

typeset -r svcproptree1_usage=$'+
[-?\n@(#)\$Id: svcproptree1 (Roland Mainz) 2010-04-02 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?svcproptree1 - SMF tree demo]
[+DESCRIPTION?\bsvcproptree1\b is a small ksh93 compound variable demo
	which reads accepts a SMF service pattern name input file,
	reads the matching service properties and converts them into an internal
	variable tree representation and outputs it in the format
	specified by viewmode (either "list", "namelist", "tree" or "compacttree")..]

pattern viewmode

[+SEE ALSO?\bksh93\b(1), \bsvcprop\b(1)]
'

while getopts -a "${progname}" "${svcproptree1_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*)	usage ;;
	esac
done
shift $((OPTIND-1))

typeset svcpattern="$1"
typeset viewmode="$2"

if [[ "${viewmode}" != ~(Elr)(list|namelist|tree|compacttree) ]] ; then
	fatal_error $"Invalid view mode \"${viewmode}\"."
fi

compound svc=(
	typeset -A proptree
)

typeset s

s="$(/usr/bin/svcprop -f "${svcpattern}")" || fatal_error $"svcprop failed with exit code $?."
print -u2 $"#loading completed."

print -r -- "$s" | svcproptovartree svc.proptree
print -u2 $"#parsing completed."

case "${viewmode}" in
	list)
		set | egrep "^svc.proptree\[" | fgrep -v ']=$'
		;;
	namelist)
		typeset + | egrep "^svc.proptree\["
		;;
	tree)
		print -v svc
		;;
	compacttree)
		print -C svc
		;;
	*)
		fatal_error $"Invalid view mode \"${viewmode}\"."
		;;
esac

print -u2 $"#done."

exit 0
# EOF.
