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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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

function debug_print
{
	# don't use "--" here to allow "-f" for formatting
#	print -u2 "$@"
	return 0
}

# Build a list of compound variables calculated from MANPATH and
# locale which contain...
# "manpath_element" - the MANPATH element this entry belongs to
# "dir"             - physical directory of "manpath_element"
# "sect"            - section (if "manpath_element" is something like /usr/share/man,1b)
# ... and put the result in the array named by argv[1]
function enumerate_mandirs
{
	nameref md=$1
	typeset manpath_element dir sect manlang
	integer i=0
    
	if [[ "${LC_MESSAGES}" != "" ]] ; then
		manlang="${LC_MESSAGES}"
	else
		manlang="${LANG}"
	fi

	print -r -- "${MANPATH//:/$'\n'}" | while read manpath_element ; do
		# strip section from manpath elements like "/usr/share/man,1b"
		dir="${manpath_element/~(E)(.*),(.*)/\1}"
		sect="${manpath_element/~(E)(.*),(.*)/\2}"
		[[ "${sect}" == "${dir}" ]] && sect=""
		
		if [[ "${manlang}" != "" && -d "${dir}/${manlang}" ]] ; then
			md+=(
				manpath_element="${manpath_element}"
				dir="${dir}/${manlang}"
				sect="${sect}"
			)
		fi
		if [[ -d "${dir}" ]] ; then
			md+=(
				manpath_element="${manpath_element}"
				dir="${dir}"
				sect="${sect}"
			)
		fi
	done
    
	return 0
}

function enumerate_mansects
{
	nameref ms=$1
	nameref mandir_node=$2
	typeset mancf="${mandir_node.dir}/man.cf"
	typeset x s l
	
	if [[ "${mandir_node.sect}" != "" ]] ; then
		x="${mandir_node.sect}"
	elif [[ "${MANSECTS}" != "" ]] ; then
		x="${MANSECTS//,/$'\n'}"
	elif [[ -f "${mancf}" && -r "${mancf}" ]] ; then
		x="$(egrep -v '^#|^[[:space:]]*$' <"${mancf}" | egrep '^MANSECTS=')"
		x="${x/MANSECTS=}/"
		x="${x//,/$'\n'}"
	else
		x="$(cd "${mandir_node.dir}" ; \
			ls -1d ~(El)(sman|man).*/ | \
			while read s ; do \
				s="${s/~(El)(sman|man)/}" ; \
				s="${s/~(Er)\//}" ; \
				print -r -- "$s" ; \
			done)"
	fi
    
	while read l ; do
		[[ "${l}" != ~(Elr)[[:blank:]]* ]] && ms+=( "${l}" )
#		print -- "sect=$l"
	done <<<"${x}"
    
#	printf "enumerate_mansects: found %d entries.\n" ${#ms[@]}

	return 0
}

# wrapper around more/less
function browse_manpage
{
	typeset tmpdirname
	typeset doc_filename="$1"
	typeset doc_title="$2"
    
	# squish characters in filename which are not allowed in a filesystem
	# (currently '/')
	doc_title="${doc_title//\//}"

	# check if we have "less" installed, if not fall back to /usr/xpg4/bin/more
	if which less >/dev/null 2>&1 ; then
		# use "cat" here to avoid that "less" may try funny things
		cat <"${doc_filename}" | less -I -M $"--prompt=MManual\ page\ ${doc_title}\ ?ltline\ %lt?L/%L.:"
	else    
		tmpdirname="$(mktemp -t -d "shman_${PPID}_$$_XXXXXX")"

		mkdir -p "${tmpdirname}" || { print -u2 -f $"Couldn't create tmp. dir %s\n" "${tmpdirname}" ; return 1 ; }

		(
			cd "${tmpdirname}"

			# note: we need to support /dev/stdin
			cat <"${doc_filename}" >"./${doc_title}"

			/usr/xpg4/bin/more "${doc_title}"

			rm -f "${doc_title}"
		)

		rmdir "${tmpdirname}"
	fi
    
	return 0
}

# /usr/bin/man <keyword>
function show_manpage
{
	compound -a mandirs
	integer i
	integer j

	enumerate_mandirs mandirs
#	debug_print -- "${mandirs[@]}"

	integer num_mandirs=${#mandirs[@]}

	for ((i=0 ; i < num_mandirs ; i++ )) ; do
		typeset mandir="${mandirs[i].dir}"
	
		typeset -a mansects
		enumerate_mansects mansects "mandirs[$i]"

		integer num_mansects="${#mansects[@]}"
#		debug_print -- "mansects=${mansects[@]}"

		for ((j=0 ; j < num_mansects ; j++ )) ; do
			typeset mansect="${mansects[j]}"

			# try 1: SGML manpage
			typeset match="${mandir}/sman${mansect}/${manname}.${mansect}"
			if [[ -r "${match}" ]] ; then
				typeset note nlink
		
				# follow SGML links if needed (needs rework, including protection against link loops)
				while true ; do
					debug_print -f "match: %s\n" "${match}"
		    
					tmp="$(cd "${mandir}" ; LC_MESSAGES=C /usr/lib/sgml/sgml2roff "${match}")"
					read note nlink <<<"${tmp}"
		
					if [[ "${note}" == ".so" ]] ; then
						match="${nlink}"
					else
						break
					fi
				done
		
				tbl <<<"${tmp}" | eqn | nroff -u0 -Tlp -man - | col -x | browse_manpage /dev/stdin "${manname}(${mansect})"
				return 0
			fi

			# try 2: troff manpage
			match="${mandir}/man${mansect}/${manname}.${mansect}"
			if [[ -r "${match}" ]] ; then
				debug_print -f "match: %s\n" "${match}"
				tbl <"${match}" | eqn | nroff -u0 -Tlp -man - | col -x | browse_manpage /dev/stdin "${manname}(${mansect})"
				return 0
			fi
		done
		unset mansects num_mansects
	done
    
	printf $"No manual entry for %s.\n" "${manname}"
	return 0
}

# /usr/bin/man -l <keyword>
function list_manpages
{
	compound -a mandirs

	enumerate_mandirs mandirs
	#debug_print -- "${mandirs[@]}"

	integer num_mandirs=${#mandirs[@]}

	for ((i=0 ; i < num_mandirs ; i++ )) ; do
		typeset mandir="${mandirs[i].dir}"

		typeset -a mansects
		enumerate_mansects mansects "mandirs[$i]"

		integer num_mansects="${#mansects[@]}"
#		debug_print -- "mansects=${mansects[@]}"

		for ((j=0 ; j < num_mansects ; j++ )) ; do
			mansect="${mansects[j]}"

			# try 1: SGML manpage
			match="${mandir}/sman${mansect}/${manname}.${mansect}"
			if [[ -r "${match}" ]] ; then
				printf "%s (%s)\t-M %s\n" "${manname}" "${mansect}" "${mandir}"
				continue
			fi

			# try 2: troff manpage
			match="${mandir}/man${mansect}/${manname}.${mansect}"
			if [[ -r "${match}" ]] ; then
				printf "%s (%s)\t-M %s\n" "${manname}" "${mansect}" "${mandir}"
				continue
			fi
		done
		unset mansects num_mansects
	done

	return 0
}

# /usr/bin/appropos
function list_keywords
{
	typeset -a mandirs
	typeset name namesec title

	enumerate_mandirs mandirs
	#debug_print -- "${mandirs[@]}"

	integer num_mandirs=${#mandirs[@]}

	for ((i=0 ; i < num_mandirs ; i++ )) ; do
		typeset mandir="${mandirs[i].dir}"
		typeset windexfile="${mandir}/windex"
	
		if [[ ! -r "${windexfile}" ]] ; then
			print -u2 -f $"%s: Can't open %s.\n" "${progname}" "${windexfile}"
			continue
		fi
	
		while IFS=$'\t' read name namesec title ; do
			if [[ "${name}${namesec}${title}" == ~(Fi)${manname} ]] ; then
				printf "%s\t%s\t%s\n" "${name}" "${namesec}" "${title}"
			fi
		done <"${windexfile}"
	done
    
	return 0
}

function usage
{
	OPTIND=0
	getopts -a "${progname}" "${man_usage}" OPT '-?'
	exit 2
}

# program start
builtin basename
builtin cat
builtin date

typeset progname="$(basename "${0}")"

typeset -r man_usage=$'+
[-?\n@(#)\$Id: shman (Roland Mainz) 2009-12-02 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[-author?Roland Mainz <roland.mainz@sun.com>]
[+NAME?man - find and display reference manual pages]
[+DESCRIPTION?The man command displays information from the reference
	manuals. It displays complete manual pages that you select
	by name, or one-line summaries selected  either  by  keyword
	(-k), or by the name of an associated file (-f). If no
	manual page is located, man prints an error message.]
[+?write me.]
[k:keyword?Prints out one-line summaries from the windex database (table of contents) that
	contain any of the given  keywords. The windex database is created using
	catman(1M).]
[l:list?Lists all manual  pages  found  matching name within the search path.]
[M:mpath?Specifies an alternate search  path  for manual  pages. path is a colon-separated
	list of directories that contain  manual page directory subtrees. For example, if
	path  is  /usr/share/man:/usr/local/man, man  searches  for  name in the standard
	location, and then /usr/local/man.  When used  with  the -k or -f options, the -M
	option must appear first. Each directory in  the  path is assumed to contain subdirectories of the form man* or sman*  ,
	one  for each section. This option overrides the MANPATH environment variable.]:[path]
[s:section?Specifies sections of the manual for man to search. The directories searched for
	name are limited to those specified by section. section can be a numerical
	digit, perhaps followed by one or more letters to match the desired section of
	the manual, for example,  "3libucb". Also, section can be a word, for example,
	local, new, old, public. section can also be a letter.
	To specify multiple sections, separate each section with
	a comma. This option overrides the MANPATH environment variable and the man.cf
	file.
	See Search Path below for an explanation of how man conducts its search.]:[section]
	
name

[+SEE ALSO?\bksh93\b(1), \bman\b(1)]
'

typeset do_list=false
typeset do_keyword=false

while getopts -a "${progname}" "${man_usage}" OPT ; do 
#    printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
	case ${OPT} in
		M)	MANPATH="${OPTARG}"	;;
		l)	do_list=true		;;
		k)	do_keyword=true		;;
		s)	MANSECTS="${OPTARG}" 	;;
		*)	usage			;;
	esac
done
shift $((OPTIND-1))

# cd /usr/man; LC_MESSAGES=C /usr/lib/sgml/sgml2roff /usr/man/sman1as/asadmin-list-timers.1as  | tbl | eqn | nroff -u0 -Tlp -man -  | col -x > /tmp/mpLQaqac

# prechecks
(( $# > 0 )) || usage

# process arguments
while (( $# > 0 )) ; do
	typeset manname="$1"
	shift

	debug_print -f "# searching for %s ...\n" "${manname}"

	if ${do_keyword} ; then
		list_keywords
	elif ${do_list} ; then
		list_manpages
	else
		show_manpage
	fi
done

# todo: better exit codes
exit 0
# EOF.
