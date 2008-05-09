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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Uses supplied "env" file, based on /opt/onbld/etc/env, to set shell variables
# before spawning a shell for doing a release-style builds interactively
# and incrementally.
#

function usage
{
    OPTIND=0
    getopts -a "${progname}" "${USAGE}" OPT '-?'
    exit 2
}

function is_source_build
{
	"${flags.s.e}" || "${flags.s.d}" || "${flags.s.h}" || "${flags.s.o}"
	return $?
}

#
# single function for setting -S flag and doing error checking.
# usage: set_S_flag <type>
# where <type> is the source build type ("E", "D", ...).
#
function set_S_flag
{
	if is_source_build; then
		print 'Can only build one source variant at a time.'
		exit 1
	fi
	
	case "$1" in
		"E") flags.s.e=true ;;
		"D") flags.s.d=true ;;
		"H") flags.s.h=true ;;
		"O") flags.s.o=true ;;
		*)   usage ;;
	esac
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
[+?bldenv is also useful if you run into build issues with the
    source product or when generating OpenSolaris deliverables.
    If a source product build is flagged, the environment is set
    up for building the indicated source product tree, which is
    assumed to have already been created. If the OpenSolaris
    deliverables flag (-O) is set in NIGHTLY_OPTIONS, the
    environment is set up for building just the open source.
    This includes using an alternate proto area, as well as
    using the closed binaries in $CODEMGR_WS/closed.skel (which
    is assumed to already exist).]
[+?By default, bldenv will invoke the shell specified in
    $SHELL. If $SHELL is not set or is invalid, csh will be
    used.]
[c?force the use of csh, regardless of the  value  of $SHELL.]
[f?invoke csh with the -f (fast-start) option. This option is valid
    only if $SHELL is unset or if it points to csh.]
[d?set up environment for doing DEBUG builds (default is non-DEBUG)]
[t?set up environment to use the tools in usr/src/tools (this is the
    default, use +t to use the tools from /opt/onbld)]
[S]:[option?Build a variant of the source product.
The value of \aoption\a must be one of the following:]{
       [+E?build the exportable source variant of the source product.]
       [+D?build the domestic  source  (exportable + crypt) variant of
           the source product.]
       [+H?build hybrid source (binaries + deleted source).]
       [+O?simulate an OpenSolaris (open source only) build.]
}

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
)

typeset progname="$(basename "${0}")"

OPTIND=1
SUFFIX="-nd"

while getopts -a "${progname}" "${USAGE}" OPT ; do 
    case ${OPT} in
	  c)	flags.c=true  ;;
	  +c)	flags.c=false ;;
	  f)	flags.f=true  ;;
	  +f)	flags.f=false ;;
	  d)	flags.d=true  SUFFIX=""    ;;
	  +d)	flags.d=false SUFFIX="-nd" ;;
	  t)	flags.t=true  ;;
	  +t)	flags.t=false ;;
	  S)	set_S_flag "$OPTARG" ;;
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

# setup environmental variables
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

#MACH=$(uname -p)

# must match the getopts in nightly.sh
OPTIND=1
NIGHTLY_OPTIONS="-${NIGHTLY_OPTIONS#-}"
while getopts '+AaBCDdFfGIilMmNnOopRrS:tUuWwXxz' FLAG "$NIGHTLY_OPTIONS"
do
	case "$FLAG" in
	  O)	flags.O=true  ;;
	  +O)	flags.O=false ;;
	  o)	flags.o=true  ;;
	  +o)	flags.o=false ;;
	  t)	flags.t=true  ;;
	  +t)	flags.t=false ;;
	  S)	set_S_flag "$OPTARG" ;;
	  *)	;;
	esac
done

export INTERNAL_RELEASE_BUILD=

print 'Build type   is  \c'
if ${flags.d} ; then
	print 'DEBUG'
	unset RELEASE_BUILD
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS
else
	# default is a non-DEBUG build
	print 'non-DEBUG'
	export RELEASE_BUILD=
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS
fi

if ${flags.O} ; then
	export MULTI_PROTO="yes"
	if [[ "$CLOSED_IS_PRESENT" == "yes" ]]; then
		print "CLOSED_IS_PRESENT is 'no' (because of '-O')"
	fi
	export CLOSED_IS_PRESENT=no
	export ON_CLOSED_BINS="$CODEMGR_WS/closed.skel"
fi

# update build-type variables
CPIODIR="${CPIODIR}${SUFFIX}"
PKGARCHIVE="${PKGARCHIVE}${SUFFIX}"

# Append source version
if "${flags.s.e}" ; then
        VERSION+=":EXPORT"
	SRC="${EXPORT_SRC}/usr/src"
fi
 
if "${flags.s.d}" ; then
        VERSION+=":DOMESTIC"
	SRC="${EXPORT_SRC}/usr/src"
fi

if "${flags.s.h}" ; then
        VERSION+=":HYBRID"
	SRC="${EXPORT_SRC}/usr/src"
fi
 
if "${flags.s.o}" ; then
        VERSION+=":OPEN_ONLY"
	SRC="${OPEN_SRCDIR}/usr/src"
fi
 
# 	Set PATH for a build
PATH="/opt/onbld/bin:/opt/onbld/bin/${MACH}:/opt/SUNWspro/bin:/usr/ccs/bin:/usr/bin:/usr/sbin:/usr/ucb:/usr/etc:/usr/openwin/bin:/usr/sfw/bin:/opt/sfw/bin:."
if [[ "${SUNWSPRO}" != "" ]]; then 
	export PATH="${SUNWSPRO}/bin:$PATH" 
fi 

if [[ -z "$CLOSED_IS_PRESENT" ]]; then
	if [[ -d $SRC/../closed ]]; then
		export CLOSED_IS_PRESENT="yes"
	else
		export CLOSED_IS_PRESENT="no"
	fi
fi

TOOLS="${SRC}/tools"
TOOLS_PROTO="${TOOLS}/proto"

if "${flags.t}" ; then
	export ONBLD_TOOLS="${ONBLD_TOOLS:=${TOOLS_PROTO}/opt/onbld}"

	export STABS="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/stabs"
	export CTFSTABS="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfstabs"
	export GENOFFSETS="${TOOLS_PROTO}/opt/onbld/bin/genoffsets"

	export CTFCONVERT="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfconvert"
	export CTFMERGE="${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfmerge"

	export CTFCVTPTBL="${TOOLS_PROTO}/opt/onbld/bin/ctfcvtptbl"
	export CTFFINDMOD="${TOOLS_PROTO}/opt/onbld/bin/ctffindmod"

	PATH="${TOOLS_PROTO}/opt/onbld/bin/${MACH}:${PATH}"
	PATH="${TOOLS_PROTO}/opt/onbld/bin:${PATH}"
	export PATH
fi


if "${flags.o}" ; then
	export CH=
else
	unset CH
fi
POUND_SIGN="#"
DEF_STRIPFLAG="-s"

TMPDIR="/tmp"

# "o_FLAG" is used by "nightly.sh" and "makebfu.sh" (it may be useful to
# rename this variable using a more descriptive name later)
export o_FLAG="$(${flags.o} && print 'y' || print 'n')"

export \
	PATH TMPDIR \
	POUND_SIGN \
	DEF_STRIPFLAG
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

"${flags.O}" && export ROOT="$ROOT-open"

if [[ "$MULTI_PROTO" != "yes" && "$MULTI_PROTO" != "no" ]]; then
	printf \
	    'WARNING: invalid value for MULTI_PROTO (%s);setting to "no".\n' \
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
        PARENT_ROOT

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


if [[ "${flags.c}" == "false" && -x "$SHELL" && \
    "$(basename "${SHELL}")" != "csh" ]]; then
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
