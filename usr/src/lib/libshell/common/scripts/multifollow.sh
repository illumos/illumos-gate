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
    print -u 2 "${progname}: $@"
    exit 1
}


function usage
{
    OPTIND=0
    getopts -a "${progname}" "${multifollow_usage}" OPT '-?'
    exit 2
}

# program start
builtin basename
builtin cat

typeset progname="$(basename "${0}")"

typeset -r multifollow_usage=$'+
[-?\n@(#)\$Id: multifollow (Roland Mainz) 2009-04-08 \$\n]
[-author?Roland Mainz <roland.mainz@nrubsig.org>]
[+NAME?multifollow - use tail -f on multiple files]
[+DESCRIPTION?\bmultifollow\b is a small utilty which can "follow" multiple
	files similar to tail -f.]

[ file ... ]

[+SEE ALSO?\bksh93\b(1), \btail\b(1)]
'

while getopts -a "${progname}" "${multifollow_usage}" OPT ; do 
#    printmsg "## OPT=|${OPT}|, OPTARG=|${OPTARG}|"
    case ${OPT} in
        *)    usage ;;
    esac
done
shift $((OPTIND-1))

# expecting at least one more arguments
(($# >= 1)) || usage

builtin -f libshell.so.1 poll || fatal_error "poll builtin not found."

typeset -a files
integer numfiles=0
integer i

# register trap to cleanup child processes
trap 'for ((i=0 ; i < numfiles ; i++ )) ; do kill -TERM ${files[i].childpid} ; done' EXIT

# setup "tail -f" childs, FIFOs and information for the "poll" builtin
for (( ; $# > 0 ; numfiles++ )) ; do
    typeset files[${numfiles}]=(
        typeset name="$1"
        typeset pipename="/tmp/multifollow_pipe_${PPID}_$$_${numfiles}"
        integer childpid=-1

        # poll(1) information
        integer fd="-1"
	typeset events="POLLIN"
	typeset revents=""
    )

    mkfifo "${files[${numfiles}].pipename}"
    redirect {files[numfiles].fd}<> "${files[numfiles].pipename}"

    tail -f "${files[${numfiles}].name}" >"${files[${numfiles}].pipename}" &
    files[${numfiles}].childpid=$!

    rm "${files[${numfiles}].pipename}"
    
    shift
done

typeset do_poll=true

# event loop
while true ; do
    if ${do_poll} ; then
        for ((i=0 ; i < numfiles ; i++ )) ; do
	    files[i].revents=""
	done
        poll files
    fi
    do_poll=true
    
    for ((i=0 ; i < numfiles ; i++ )) ; do
        if [[ "${files[i].revents}" != "" ]] ; then
	    # todo: investigate why we have to use "do_poll" at all - AFAIK it
	    # should be sufficient to call "poll" and get "revents" set if there
	    # are any remaining data...
	    if read -t0 -u${files[i].fd} line ; then
	        print -- "#${i}: ${line}"
		do_poll=false        
	    fi
	fi
    done
done

fatal_error "not reached."
# EOF.
