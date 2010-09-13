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
# cpvprint - compound variable pretty printer
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

function prettyprint_compoundvar
{
	nameref var=$1

	# print tree
	str="${ print -v var ; }"
	# do some "pretty-printing" for human users (the output is still a
	# valid compound variable value)
	# (note: This does not scale well with large files)
	str="${str//$'\t'typeset -l -E /$'\t'float }"
	str="${str//$'\t'typeset -l -i /$'\t'integer }"
	str="${str//$'\t'typeset -C /$'\t'compound }"
	print -r -- "${str}"

	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${cpvprint_usage}" OPT '-?'
	exit 2
}

# HTML constants
compound -r hc=(
	compound -r doctype=(
		compound -r xhtml=(
			typeset -r transitional=$'<!DOCTYPE html\n\tPUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n\t"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'
		)
	)
	compound -r namespace=(
		typeset -r xhtml=$'http://www.w3.org/1999/xhtml'
	)
	typeset -r xml_head=$'<?xml version="1.0" encoding="UTF-8"?>\n'
)

# main
builtin basename

set -o noglob
set -o errexit
set -o nounset

# tree variable
compound tree

typeset progname="${ basename "${0}" ; }"

typeset -r cpvprint_usage=$'+
[-?\n@(#)\$Id: cpvprint (Roland Mainz) 2009-06-15 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?cpvprint - render compound variable trees in various formats]
[+DESCRIPTION?\bcpvprint\b is converter which reads a ksh compound
	variable and prints it on a different format. Supported
	formats are \'default\', \'altdefault\',
	\'tree\', \'alttree\',
	\'pretty\', \'pretty.html\', \'list\' and \'fulllist\']

format [ arguments ]

[+SEE ALSO?\bksh93\b(1), \bcpvlint\b(1)]
'

while getopts -a "${progname}" "${cpvprint_usage}" OPT ; do 
#	printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		*) usage ;;
	esac
done
shift $((OPTIND-1))

# prechecks
(( $# > 0 )) || usage

printformat="$1"
shift

# read variable
case $# in
	0)
		read -C tree || fatal_error $"Read error."
		;;
	1)
		integer fd

		redirect {fd}<> "$1" || fatal_error $"Cannot open file."
		read -u${fd} -C tree || fatal_error $"Read error."
		redirect {fd}<&- || fatal_error $"Close error."
		;;
	2)
		print -u2 -f $"%s: Unsupported number of arguments.\n" "$0"
		exit 1
		;;
esac

# print variable
case ${printformat} in
	'default' | 'tree')
		print -v tree
		;;
	'altdefault' | 'alttree')
		print -C tree
		;;
	'pretty')
		# print variable tree (same as $ print -v filetree # except that it "looks better")
		prettyprint_compoundvar tree
		;;
	'pretty.html')
		printf '%s%s<html xmlns="%s" xml:lang="en" lang="en">\n<head><meta name="generator" content="%H" /><title>%H</title></head>\n<body><pre>%H\n</pre></body></html>\n' \
			"${hc.xml_head}" \
			"${hc.doctype.xhtml.transitional}" \
			"${hc.namespace.xhtml}" \
			"ksh Compound Variable Pretty Printer (cpvprint)" \
			"" \
			"$(prettyprint_compoundvar tree)" | iconv -f "UTF-8" - -
		;;
	'list')
		set | egrep '^tree.' | sed 's/^tree\.//' | egrep -v '^[[:alnum:]]+(\.([[:alnum:]\.]+)(\[.*\])*)*=\('
		;;
	'fulllist')
		set | egrep "^tree."
		;;
	*)
		fatal_error $"Unsupported format."
		;;
esac

exit 0
# EOF.
