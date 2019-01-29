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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2018 Joyent, Inc.
#
# Uses supplied "env" file, based on /opt/onbld/etc/env, to set shell variables
# before spawning a shell for doing a release-style builds interactively
# and incrementally.
#

function fatal_error
{
	print -u2 "${progname}: $*"
	exit 1
}

function usage
{
    OPTIND=0
    getopts -a "${progname}" "${USAGE}" OPT '-?'
    exit 2
}

typeset -r USAGE=$'+
[-?\n@(#)\$Id: bldenv (OS/Net) 2008-04-06 \$\n]
[-author?OS/Net community <tools-discuss@opensolaris.org>]
[+NAME?bldenv - spawn shell for interactive incremental OS-Net
    consolidation builds]
[+DESCRIPTION?bldenv is a useful companion to the nightly(1) script for
    doing interactive and incremental builds in a workspace
    already built with nightly(1). bldenv spawns a shell set up
    with the same environment variables taken from an env_file,
    as prepared for use with nightly(1).]
[+?In addition to running a shell for interactive use, bldenv
    can optionally run a single command in the given environment,
    in the vein of sh -c or su -c. This is useful for
    scripting, when an interactive shell would not be. If the
    command is composed of multiple shell words or contains
    other shell metacharacters, it must be quoted appropriately.]
[+?bldenv is particularly useful for testing Makefile targets
    like clobber, install and _msg, which otherwise require digging
    through large build logs to figure out what is being
    done.]
[+?By default, bldenv will invoke the shell specified in
    $SHELL. If $SHELL is not set or is invalid, csh will be
    used.]
[c?force the use of csh, regardless of the  value  of $SHELL.]
[f?invoke csh with the -f (fast-start) option. This option is valid
    only if $SHELL is unset or if it points to csh.]
[d?set up environment for doing DEBUG builds. The default is non-DEBUG,
    unless the -F flag is specified in the nightly file.]
[t?set up environment to use the tools in usr/src/tools (this is the
    default, use +t to use the tools from /opt/onbld)]

<env_file> [command]

[+EXAMPLES]{
    [+?Example 1: Interactive use]{
        [+?Use bldenv to spawn a shell to perform  a  DEBUG  build  and
            testing of the  Makefile  targets  clobber and install for
            usr/src/cmd/true.]
        [+\n% rlogin wopr-2 -l gk
{root::wopr-2::49} bldenv -d /export0/jg/on10-se.env
Build type   is  DEBUG
RELEASE      is  5.10
VERSION      is  wopr-2::on10-se::11/01/2001
RELEASE_DATE is  May 2004
The top-level `setup\' target is available to build headers
and tools.
Using /usr/bin/tcsh as shell.
{root::wopr-2::49}
{root::wopr-2::49} cd $SRC/cmd/true
{root::wopr-2::50} make
{root::wopr-2::51} make clobber
/usr/bin/rm -f true true.po
{root::wopr-2::52} make
/usr/bin/rm -f true
cat true.sh > true
chmod +x true
{root::wopr-2::53} make install
install -s -m 0555 -u root -g bin -f /export0/jg/on10-se/proto/root_sparc/usr/bin true
`install\' is up to date.]
    }
    [+?Example 2: Non-interactive use]{
        [+?Invoke bldenv to create SUNWonbld with a single command:]
        [+\nexample% bldenv onnv_06 \'cd $SRC/tools && make pkg\']
        }
}
[+SEE ALSO?\bnightly\b(1)]
'

# main
builtin basename

# boolean flags (true/false)
typeset flags=(
	typeset c=false
	typeset f=false
	typeset d=false
	typeset O=false
	typeset o=false
	typeset t=true
	typeset s=(
		typeset e=false
		typeset h=false
		typeset d=false
		typeset o=false
	)
	typeset d_set=false
	typeset DF_build=false
)

typeset progname="$(basename -- "${0}")"

OPTIND=1

while getopts -a "${progname}" "${USAGE}" OPT ; do
    case ${OPT} in
	  c)	flags.c=true  ;;
	  +c)	flags.c=false ;;
	  f)	flags.f=true  ;;
	  +f)	flags.f=false ;;
	  d)	flags.d=true ; flags.d_set=true ;;
	  +d)	flags.d=false ; flags.d_set=true ;;
	  t)	flags.t=true  ;;
	  +t)	flags.t=false ;;
	  \?)	usage ;;
    esac
done
shift $((OPTIND-1))

# test that the path to the environment-setting file was given
if (( $# < 1 )) ; then
	usage
fi

# force locale to C
export \
	LANG=C \
	LC_ALL=C \
	LC_COLLATE=C \
	LC_CTYPE=C \
	LC_MESSAGES=C \
	LC_MONETARY=C \
	LC_NUMERIC=C \
	LC_TIME=C

# clear environment variables we know to be bad for the build
unset \
	LD_OPTIONS \
	LD_LIBRARY_PATH \
	LD_AUDIT \
	LD_BIND_NOW \
	LD_BREADTH \
	LD_CONFIG \
	LD_DEBUG \
	LD_FLAGS \
	LD_LIBRARY_PATH_64 \
	LD_NOVERSION \
	LD_ORIGIN \
	LD_LOADFLTR \
	LD_NOAUXFLTR \
	LD_NOCONFIG \
	LD_NODIRCONFIG \
	LD_NOOBJALTER \
	LD_PRELOAD \
	LD_PROFILE \
	CONFIG \
	GROUP \
	OWNER \
	REMOTE \
	ENV \
	ARCH \
	CLASSPATH

#
# Setup environment variables
#
if [[ -f /etc/nightly.conf ]]; then
	source /etc/nightly.conf
fi

if [[ -f "$1" ]]; then
	if [[ "$1" == */* ]]; then
		source "$1"
	else
		source "./$1"
	fi
else
	if [[ -f "/opt/onbld/env/$1" ]]; then
		source "/opt/onbld/env/$1"
	else
		printf \
		    'Cannot find env file as either %s or /opt/onbld/env/%s\n' \
		    "$1" "$1"
		exit 1
	fi
fi
shift

# contents of stdenv.sh inserted after next line:
# STDENV_START
# STDENV_END

# Check if we have sufficient data to continue...
[[ -v CODEMGR_WS ]] || fatal_error "Error: Variable CODEMGR_WS not set."
[[ -d "${CODEMGR_WS}" ]] || fatal_error "Error: ${CODEMGR_WS} is not a directory."
[[ -f "${CODEMGR_WS}/usr/src/Makefile" ]] || fatal_error "Error: ${CODEMGR_WS}/usr/src/Makefile not found."

# must match the getopts in nightly.sh
OPTIND=1
NIGHTLY_OPTIONS="-${NIGHTLY_OPTIONS#-}"
while getopts '+0ABCDdFfGIilMmNnpRrtUuwW' FLAG $NIGHTLY_OPTIONS
do
	case "$FLAG" in
	  t)	flags.t=true  ;;
	  +t)	flags.t=false ;;
	  F)	flags.DF_build=true ;;
	  *)	;;
	esac
done

# DEBUG is a little bit complicated.  First, bldenv -d/+d over-rides
# the env file.  Otherwise, we'll default to DEBUG iff we are *not*
# building non-DEBUG bits at all.
if [ "${flags.d_set}" != "true" ] && "${flags.DF_build}"; then
	flags.d=true
fi

POUND_SIGN="#"
# have we set RELEASE_DATE in our env file?
if [ -z "$RELEASE_DATE" ]; then
	RELEASE_DATE=$(LC_ALL=C date +"%B %Y")
fi
BUILD_DATE=$(LC_ALL=C date +%Y-%b-%d)
BASEWSDIR=$(basename -- "${CODEMGR_WS}")
DEV_CM="\"@(#)SunOS Internal Development: $LOGNAME $BUILD_DATE [$BASEWSDIR]\""
export DEV_CM RELEASE_DATE POUND_SIGN

print 'Build type   is  \c'
if ${flags.d} ; then
	print 'DEBUG'
	SUFFIX=""
	unset RELEASE_BUILD
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS
else
	# default is a non-DEBUG build
	print 'non-DEBUG'
	SUFFIX="-nd"
	export RELEASE_BUILD=
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS
fi

# update build-type variables
PKGARCHIVE="${PKGARCHIVE}${SUFFIX}"

#	Set PATH for a build
PATH="/opt/onbld/bin:/opt/onbld/bin/${MACH}:/opt/SUNWspro/bin:/usr/ccs/bin:/usr/bin:/usr/sbin:/usr/ucb:/usr/etc:/usr/openwin/bin:/usr/sfw/bin:/opt/sfw/bin:."
if [[ "${SUNWSPRO}" != "" ]]; then
	export PATH="${SUNWSPRO}/bin:$PATH"
fi

if [[ -n "${MAKE}" ]]; then
	if [[ -x "${MAKE}" ]]; then
		export PATH="$(dirname -- "${MAKE}"):$PATH"
	else
		print "\$MAKE (${MAKE}) is not a valid executible"
		exit 1
	fi
fi

TOOLS="${SRC}/tools"
TOOLS_PROTO="${TOOLS}/proto/root_${MACH}-nd" ; export TOOLS_PROTO

if "${flags.t}" ; then
	export ONBLD_TOOLS="${ONBLD_TOOLS:=${TOOLS_PROTO}/opt/onbld}"

	export STABS="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/stabs"
	export CTFSTABS="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfstabs"
	export GENOFFSETS="${TOOLS_PROTO}/opt/onbld/bin/genoffsets"

	export CTFCONVERT="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfconvert"
	export CTFMERGE="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfmerge"
	export NDRGEN="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ndrgen"

	PATH="${TOOLS_PROTO}/opt/onbld/bin/${MACH}:${PATH}"
	PATH="${TOOLS_PROTO}/opt/onbld/bin:${PATH}"
	export PATH
fi

export DMAKE_MODE=${DMAKE_MODE:-parallel}

#
# Work around folks who have historically used GCC_ROOT and convert it to
# GNUC_ROOT. We leave GCC_ROOT in the environment for now (though this could
# mess up the case where multiple different gcc versions are being used to
# shadow).
#
if [[ -n "${GCC_ROOT}" ]]; then
	export GNUC_ROOT=${GCC_ROOT}
fi

DEF_STRIPFLAG="-s"

TMPDIR="/tmp"

export \
	PATH TMPDIR \
	POUND_SIGN \
	DEF_STRIPFLAG \
	RELEASE_DATE
unset \
	CFLAGS \
	LD_LIBRARY_PATH

# a la ws
ENVLDLIBS1=
ENVLDLIBS2=
ENVLDLIBS3=
ENVCPPFLAGS1=
ENVCPPFLAGS2=
ENVCPPFLAGS3=
ENVCPPFLAGS4=
PARENT_ROOT=
PARENT_TOOLS_ROOT=

if [[ "$MULTI_PROTO" != "yes" && "$MULTI_PROTO" != "no" ]]; then
	printf \
	    'WARNING: invalid value for MULTI_PROTO (%s); setting to "no".\n' \
	    "$MULTI_PROTO"
	export MULTI_PROTO="no"
fi

[[ "$MULTI_PROTO" == "yes" ]] && export ROOT="${ROOT}${SUFFIX}"

ENVLDLIBS1="-L$ROOT/lib -L$ROOT/usr/lib"
ENVCPPFLAGS1="-I$ROOT/usr/include"
MAKEFLAGS=e

export \
        ENVLDLIBS1 \
        ENVLDLIBS2 \
        ENVLDLIBS3 \
	ENVCPPFLAGS1 \
        ENVCPPFLAGS2 \
        ENVCPPFLAGS3 \
	ENVCPPFLAGS4 \
        MAKEFLAGS \
        PARENT_ROOT \
        PARENT_TOOLS_ROOT

printf 'RELEASE      is %s\n'   "$RELEASE"
printf 'VERSION      is %s\n'   "$VERSION"
printf 'RELEASE_DATE is %s\n\n' "$RELEASE_DATE"

if [[ -f "$SRC/Makefile" ]] && egrep -s '^setup:' "$SRC/Makefile" ; then
	print "The top-level 'setup' target is available \c"
	print "to build headers and tools."
	print ""

elif "${flags.t}" ; then
	printf \
	    'The tools can be (re)built with the install target in %s.\n\n' \
	    "${TOOLS}"
fi

#
# place ourselves in a new task, respecting BUILD_PROJECT if set.
#
/usr/bin/newtask -c $$ ${BUILD_PROJECT:+-p$BUILD_PROJECT}

if [[ "${flags.c}" == "false" && -x "$SHELL" && \
    "$(basename -- "${SHELL}")" != "csh" ]]; then
	# $SHELL is set, and it's not csh.

	if "${flags.f}" ; then
		print 'WARNING: -f is ignored when $SHELL is not csh'
	fi

	printf 'Using %s as shell.\n' "$SHELL"
	exec "$SHELL" ${@:+-c "$@"}

elif "${flags.f}" ; then
	print 'Using csh -f as shell.'
	exec csh -f ${@:+-c "$@"}

else
	print 'Using csh as shell.'
	exec csh ${@:+-c "$@"}
fi

# not reached
