#!/bin/ksh -p
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Uses supplied "env" file, based on /opt/onbld/etc/env, to set shell variables
# before spawning a shell for doing a release-style builds interactively
# and incrementally.
#
USAGE='Usage: bldenv [-fdt] [ -S E|D|H ] <env_file> [ command ]

Where:
	-c	Force the use of csh - ignore $SHELL
	-f	Invoke csh with -f
	-d	Setup a DEBUG build (default: non-DEBUG)
	-t	use the tools in $SRC/tools
	-S	Build a variant of the source product
		E - build exportable source
		D - build domestic source (exportable + crypt)
		H - build hybrid source (binaries + deleted source)
'

c_FLAG=n
f_FLAG=n
d_FLAG=n
o_FLAG=n
t_FLAG=n
SE_FLAG=n
SH_FLAG=n
SD_FLAG=n

OPTIND=1
SUFFIX="-nd"
while getopts cdfS:t FLAG
do
	case $FLAG in
	  c )	c_FLAG=y
		;;
	  f )	f_FLAG=y
		;;
	  d )	d_FLAG=y
		SUFFIX=""
		;;
	  t )	t_FLAG=y
		;;
	  S )
		if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
			echo "Can only build one source variant at a time."
			exit 1
		fi
		if [ "${OPTARG}" = "E" ]; then
			SE_FLAG=y
		elif [ "${OPTARG}" = "D" ]; then
			SD_FLAG=y
		elif [ "${OPTARG}" = "H" ]; then
			SH_FLAG=y
		else
			echo "$USAGE"
			exit 1
		fi
		;;
	  \?)	echo "$USAGE"
		exit 1
		;;
	esac
done

# correct argument count after options
shift `expr $OPTIND - 1`

# test that the path to the environment-setting file was given
if [ $# -lt 1 ]
then
	echo "$USAGE"
	exit 1
fi

# force locale to C
LC_COLLATE=C;   export LC_COLLATE
LC_CTYPE=C;     export LC_CTYPE
LC_MESSAGES=C;  export LC_MESSAGES
LC_MONETARY=C;  export LC_MONETARY
LC_NUMERIC=C;   export LC_NUMERIC
LC_TIME=C;      export LC_TIME

# clear environment variables we know to be bad for the build
unset LD_OPTIONS LD_LIBRARY_PATH LD_AUDIT LD_BIND_NOW LD_BREADTH LD_CONFIG
unset LD_DEBUG LD_FLAGS LD_LIBRARY_PATH_64 LD_NOVERSION LD_ORIGIN 
unset LD_LOADFLTR LD_NOAUXFLTR LD_NOCONFIG LD_NODIRCONFIG LD_NOOBJALTER 
unset LD_PRELOAD LD_PROFILE  
unset CONFIG
unset GROUP
unset OWNER
unset REMOTE
unset ENV
unset ARCH
unset CLASSPATH 

# setup environmental variables
if [ -f $1 ]; then
	if [[ $1 = */* ]]; then
		. $1
	else
		. ./$1
	fi
else
	if [ -f /opt/onbld/env/$1 ]; then
		. /opt/onbld/env/$1
	else
		echo "Cannot find env file as either $1 or /opt/onbld/env/$1"
		exit 1
	fi
fi
shift

#MACH=`uname -p`

if [ -z "$CLOSED_IS_PRESENT" ]; then
	if [ -d $SRC/../closed ]; then
		CLOSED_IS_PRESENT="yes"
	else
		CLOSED_IS_PRESENT="no"
	fi
	export CLOSED_IS_PRESENT
fi

# must match the getopts in nightly.sh
OPTIND=1
NIGHTLY_OPTIONS=-${NIGHTLY_OPTIONS#-}
while getopts ABDFMNCGIRafinlmoptuUxdrtwzWS:X FLAG $NIGHTLY_OPTIONS
do
	case $FLAG in
	  t )	t_FLAG=y
		;;
	  S )
		if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" -o "$SH_FLAG" = "y" ]; then
			echo "Can only build one source variant at a time."
			exit 1
		fi
		if [ "${OPTARG}" = "E" ]; then
			SE_FLAG=y
		elif [ "${OPTARG}" = "D" ]; then
			SD_FLAG=y
		elif [ "${OPTARG}" = "H" ]; then
			SH_FLAG=y
		else
			echo "$USAGE"
			exit 1
		fi
		;;
	  o)	o_FLAG=y
		;;
	  *)    ;;
	esac
done

echo "Build type   is  \c"
if [ ${d_FLAG} = "y" ]; then
	echo "DEBUG"
	export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
	unset RELEASE_BUILD
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS
else
	# default is a non-DEBUG build
	echo "non-DEBUG"
	export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
	export RELEASE_BUILD ; RELEASE_BUILD=
	unset EXTRA_OPTIONS
	unset EXTRA_CFLAGS
fi

# update build-type variables
CPIODIR=${CPIODIR}${SUFFIX}
PKGARCHIVE=${PKGARCHIVE}${SUFFIX}

if [ "$SE_FLAG" = "y" -o "$SD_FLAG" = "y" ]; then
        if [ -z "${EXPORT_SRC}" ]; then
                echo "EXPORT_SRC must be set for a source build."
                exit 1
        fi
        if [ -z "${CRYPT_SRC}" ]; then
                echo "CRYPT_SRC must be set for a source build."
                exit 1
        fi
fi

if [ "$SH_FLAG" = "y" ]; then
        if [ -z "${EXPORT_SRC}" ]; then
                echo "EXPORT_SRC must be set for a source build."
                exit 1
        fi
fi
 
# Append source version
if [ "$SE_FLAG" = "y" ]; then
        VERSION="${VERSION}:EXPORT"
	SRC=${EXPORT_SRC}/usr/src
fi
 
if [ "$SD_FLAG" = "y" ]; then
        VERSION="${VERSION}:DOMESTIC"
	SRC=${EXPORT_SRC}/usr/src
fi

if [ "$SH_FLAG" = "y" ]; then
        VERSION="${VERSION}:HYBRID"
	SRC=${EXPORT_SRC}/usr/src
fi
 
# 	Set PATH for a build
PATH="/opt/onbld/bin:/opt/onbld/bin/${MACH}:/opt/SUNWspro/bin:/usr/ccs/bin:/usr/bin:/usr/sbin:/usr/ucb:/usr/etc:/usr/openwin/bin:/usr/sfw/bin:/opt/sfw/bin:."
if [ "${SUNWSPRO}" != "" ]; then 
	PATH="${SUNWSPRO}/bin:$PATH" 
	export PATH 
fi 

TOOLS=${SRC}/tools
TOOLS_PROTO=${TOOLS}/proto

if [ "$t_FLAG" = "y" ]; then
	export ONBLD_TOOLS=${ONBLD_TOOLS:=${TOOLS_PROTO}/opt/onbld}

	STABS=${TOOLS_PROTO}/opt/onbld/bin/${MACH}/stabs
	export STABS
	CTFSTABS=${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfstabs
	export CTFSTABS
	GENOFFSETS=${TOOLS_PROTO}/opt/onbld/bin/genoffsets
	export GENOFFSETS

	CTFCONVERT=${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfconvert
	export CTFCONVERT
	CTFMERGE=${TOOLS_PROTO}/opt/onbld/bin/${MACH}/ctfmerge
	export CTFMERGE

	CTFCVTPTBL=${TOOLS_PROTO}/opt/onbld/bin/ctfcvtptbl
	export CTFCVTPTBL
	CTFFINDMOD=${TOOLS_PROTO}/opt/onbld/bin/ctffindmod
	export CTFFINDMOD

	PATH="${TOOLS_PROTO}/opt/onbld/bin/${MACH}:${PATH}"
	PATH="${TOOLS_PROTO}/opt/onbld/bin:${PATH}"
	export PATH
fi

unset CH
if [ "$o_FLAG" = "y" ]; then
	CH=
	export CH
fi
POUND_SIGN="#"
DEF_STRIPFLAG="-s"

TMPDIR="/tmp"

export	PATH TMPDIR o_FLAG POUND_SIGN DEF_STRIPFLAG
unset	CFLAGS LD_LIBRARY_PATH

# a la ws
ENVLDLIBS1=
ENVLDLIBS2=
ENVLDLIBS3=
ENVCPPFLAGS1=
ENVCPPFLAGS2=
ENVCPPFLAGS3=
ENVCPPFLAGS4=
PARENT_ROOT=

ENVLDLIBS1="-L$ROOT/lib -L$ROOT/usr/lib"
ENVCPPFLAGS1="-I$ROOT/usr/include"
MAKEFLAGS=e

export ENVLDLIBS1 ENVLDLIBS2 ENVLDLIBS3 \
	ENVCPPFLAGS1 ENVCPPFLAGS2 ENVCPPFLAGS3 \
	ENVCPPFLAGS4 MAKEFLAGS PARENT_ROOT

echo "RELEASE      is  $RELEASE"
echo "VERSION      is  $VERSION"
echo "RELEASE_DATE is  $RELEASE_DATE"
echo ""

if [[ -f $SRC/Makefile ]] && egrep -s '^setup:' $SRC/Makefile; then
	echo "The top-level 'setup' target is available \c"
	echo "to build headers and tools."
	echo ""

elif [[ "$t_FLAG" = "y" ]]; then
	echo "The tools can be (re)built with the install target in ${TOOLS}."
	echo ""
fi


if [[ "$c_FLAG" = "n" && -x "$SHELL" && `basename $SHELL` != "csh" ]]; then
	# $SHELL is set, and it's not csh.

	if [[ "$f_FLAG" != "n" ]]; then
		echo "WARNING: -f is ignored when \$SHELL is not csh"
	fi

	echo "Using $SHELL as shell."
	exec $SHELL ${@:+-c "$@"}

elif [[ "$f_FLAG" = "y" ]]; then
	echo "Using csh -f as shell."
	exec csh -f ${@:+-c "$@"}

else
	echo "Using csh as shell."
	exec csh ${@:+-c "$@"}
fi
