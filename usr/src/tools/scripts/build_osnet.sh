#!/bin/ksh
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This script can be used to build the ON component of the source product.
# It should _not_ be used by developers, since it does not work with
# workspaces, or do many of the features that 'nightly' uses to help you
# (like detection errors and warnings, and send mail on completion).
# 'nightly' (and other tools we use) lives in usr/src/tools.
#
# examine arguments. Source customers probably use no arguments, which just
# builds in usr/src from the current directory. They might want to use
# the -B flag, but the others are for use internally for testing the
# compressed cpio archives we deliver to the folks who build the source product.
#

#
# The CDPATH variable causes ksh's `cd' builtin to emit messages to stdout
# under certain circumstances, which can really screw things up; unset it.
#
unset CDPATH

USAGE='build_osnet [-B dir] [-E export_archive ] [-C crypt_archive ]
	[ -H binary_archive ] [-D] [-P]

where:
    -B dir              - set build directory
    -E export_archive   - create build directory from export_archive
    -C crypt_archive    - extract crypt_archive on top of build area
    -H binary_archive   - extract binary_archive on top of build area
    -D                  - do a DEBUG build
    -P                  - do not copy packages to /pkgs
'

BUILDAREA=`pwd`
EXPORT_CPIO=
CRYPT_CPIO=
BINARY_CPIO=
DEBUGFLAG="n"
PKGCPFLAG="y"

OPTIND=1
while getopts B:E:C:H:DP FLAG
do
	case $FLAG in
	  B )	BUILDAREA="$OPTARG"
		;;
	  E )	EXPORT_CPIO="$OPTARG"
		;;
	  C )	CRYPT_CPIO="$OPTARG"
		;;
	  H )	BINARY_CPIO="$OPTARG"
		;;
	  D )	DEBUGFLAG="y"
		;;
	  P )	PKGCPFLAG="n"
		;;
	 \? )	echo "$USAGE"
		exit 1
		;;
	esac
done


# extract source

# verify you are root
/usr/bin/id | grep root >/dev/null 2>&1
if [ "$?" != "0" ]; then
	echo \"$0\" must be run as root.
	exit 1
fi

if [ ! -z "${EXPORT_CPIO}" -a ! -f "${EXPORT_CPIO}" ]; then
	echo "${EXPORT_CPIO} does not exist - aborting."
	exit 1
fi

if [ -z "${BUILDAREA}" ]; then
	echo "BUILDAREA must be set - aborting."
	exit 1
fi

if [ -z "${SPRO_ROOT}" ]; then
	echo
	echo "SPRO_ROOT is not set - defaulting to /opt/SUNWspro."
	echo "If your compilers are located at a different location,"
	echo "you will need to set the SPRO_ROOT variable before"
	echo "you execute this script."
	echo
	SPRO_ROOT=/opt/SUNWspro;	export SPRO_ROOT
fi

if [ -z "${JAVA_ROOT}" ]; then
	echo "JAVA_ROOT is not set - defaulting to /usr/java."
	JAVA_ROOT=/usr/java;		export JAVA_ROOT
fi

# in case you use dmake. Note that dmake on ON has only been
# tested in parallel make mode.
if [ -z "${DMAKE_MAX_JOBS}" ]; then
	DMAKE_MAX_JOBS=4;
	export DMAKE_MAX_JOBS
fi
DMAKE_MODE=parallel; export DMAKE_MODE

################################################################
# Uncomment the line below to change to a parallel make using
# dmake. Be sure to put a "#" in front of the other make line.
# dmake can help create builds much faster, though if
# you have problems you should go back to serial make.
################################################################
#MAKE=dmake;				export MAKE
MAKE=/usr/ccs/bin/make;				export MAKE

#
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

# set magic variables

MACH=`uname -p`;			export MACH
ROOT="${BUILDAREA}/proto/root_${MACH}";	export ROOT
SRC="${BUILDAREA}/usr/src";		export SRC
TOOLS_PROTO="${SRC}/tools/proto/root_${MACH}-nd";	export TOOLS_PROTO
PKGARCHIVE="${BUILDAREA}/packages/${MACH}";	export PKGARCHIVE
UT_NO_USAGE_TRACKING="1";		export UT_NO_USAGE_TRACKING
RPCGEN=/usr/bin/rpcgen;			export RPCGEN
TMPDIR=/tmp;				export TMPDIR
ONBLD_ROOT=/tmp/opt/onbld;		export ONBLD_ROOT
STABS=${ONBLD_ROOT}/bin/sparc/stabs;	export STABS
CTFSTABS=${ONBLD_ROOT}/bin/${MACH}/ctfstabs;	 export CTFSTABS
CTFCONVERT=${ONBLD_ROOT}/bin/${MACH}/ctfconvert; export CTFCONVERT
CTFCVTPTBL=${ONBLD_ROOT}/bin/ctfcvtptbl;	 export CTFCVTPTBL
CTFFINDMOD=${ONBLD_ROOT}/bin/ctffindmod;	 export CTFFINDMOD
CTFMERGE=${ONBLD_ROOT}/bin/${MACH}/ctfmerge;	 export CTFMERGE
ENVLDLIBS1=
ENVLDLIBS2=
ENVLDLIBS3=
ENVCPPFLAGS1=
ENVCPPFLAGS2=
ENVCPPFLAGS3=
ENVCPPFLAGS4=
export ENVLDLIBS3 ENVCPPFLAGS1 ENVCPPFLAGS2 ENVCPPFLAGS3 ENVCPPFLAGS4
unset RELEASE RELEASE_DATE

ENVLDLIBS1="-L$ROOT/lib -L$ROOT/usr/lib"
ENVCPPFLAGS1="-I$ROOT/usr/include"

export ENVLDLIBS1 ENVLDLIBS2

export INTERNAL_RELEASE_BUILD ; INTERNAL_RELEASE_BUILD=
export RELEASE_BUILD ; RELEASE_BUILD=
unset EXTRA_OPTIONS
unset EXTRA_CFLAGS

if [ "${DEBUGFLAG}" = "y" ]; then
	unset RELEASE_BUILD
fi

unset CFLAGS LD_LIBRARY_PATH LD_OPTIONS

PATH="/opt/SUNWspro/bin:/usr/ccs/bin:/usr/bin:/usr/sbin"
export PATH

if [ -z "${ROOT}" ]; then
	echo "ROOT must be set - aborting."
	exit 1
fi

if [ -z "${PKGARCHIVE}" ]; then
	echo "PKGARCHIVE must be set - aborting."
	exit 1
fi

if [ -d "${BUILDAREA}" ]; then
	if [ -z "${EXPORT_CPIO}" ]; then
		# clobber doesn't work on the free source product,
		# since it will destroy the preinstalled object modules
		# so we just comment it out for now
		echo "\n==== Not clobbering in ${BUILDAREA} ====\n"
		#echo "\n==== Clobbering in ${BUILDAREA} ====\n"
		#cd $SRC
		#rm -f clobber.out
		#/bin/time ${MAKE} -e clobber | tee -a clobber.out
		#find . -name SCCS -prune -o \
		#    \( -name '.make.*' -o -name 'lib*.a' -o -name 'lib*.so*' -o \
		#    -name '*.o' \) \
		#    -exec rm -f {} \;

	else
		echo "\n==== Removing ${BUILDAREA} ====\n"
		sleep 15
		rm -rf ${BUILDAREA}
	fi
fi

if [ -d "${ROOT}" ]; then
	echo "\n==== Removing ${ROOT} ====\n"
	sleep 15
	rm -rf ${ROOT}
fi

if [ -d "${PKGARCHIVE}" ]; then
	echo "\n==== Removing ${PKGARCHIVE} ====\n"
	sleep 15
	rm -rf ${PKGARCHIVE}
fi

mkdir -p ${BUILDAREA}

cd ${BUILDAREA}

if [ ! -z "${EXPORT_CPIO}" ]; then
	echo "\n==== Extracting export source ====\n"
	zcat ${EXPORT_CPIO} | cpio -idmucB
fi

# hack
if [ -d usr/src/cmd/sendmail ]; then
	VERSION="Source"
else
	VERSION="MODIFIED_SOURCE_PRODUCT"
fi

if [ ! -z "${CRYPT_CPIO}" -a -f "${CRYPT_CPIO}" ]; then
	echo "\n==== Extracting crypt source ====\n"
	zcat ${CRYPT_CPIO} | cpio -idmucB
	VERSION="Source:Crypt"
	echo "\n==== Performing crypt build ====\n"
elif [ ! -z "${BINARY_CPIO}" -a -f "${BINARY_CPIO}" ]; then
	echo "\n==== Extracting binary modules ====\n"
	zcat ${BINARY_CPIO} | cpio -idmucB
	VERSION="MODIFIED_SOURCE_PRODUCT"
	echo "\n==== Performing hybrid build ====\n"
else
	VERSION="Source:Export"
	echo "\n==== Performing export build ====\n"
fi
export VERSION

echo "\n==== Disk space used (Source) ====\n"

cd ${BUILDAREA}
/usr/bin/du -s -k usr

mkdir -p ${ROOT}
mkdir -p ${PKGARCHIVE}

echo "\n==== Building osnet tools ====\n"
rm -rf /tmp/opt
cd $SRC/tools;
rm -f install.out
export BUILD_TOOLS=/tmp/opt
/bin/time env TOOLS_PROTO=/tmp ${MAKE} -e install | tee -a install.out
PATH="${ONBLD_ROOT}/bin:${ONBLD_ROOT}/bin/${MACH}:$PATH"
export PATH

echo "\n==== Build environment ====\n"
env

if [ "${DEBUGFLAG}" = "y" ]; then
	echo "\n==== Building osnet (DEBUG) ====\n"
else
	echo "\n==== Building osnet ====\n"
fi

cd $SRC
rm -f install.out
/bin/time ${MAKE} -e install | tee -a install.out

echo "\n==== Build errors ====\n"

egrep ":" install.out | \
	egrep -e "(${MAKE}:|[ 	]error[: 	\n])" | \
	egrep -v warning

echo "\n==== Building osnet packages ====\n"
cd $SRC/pkg
rm -f install.out
/bin/time ${MAKE} -e install | tee -a install.out

echo "\n==== Package build errors ====\n"

egrep "${MAKE}|ERROR|WARNING" $SRC/pkg/install.out | \
	grep ':' | \
	grep -v PSTAMP

echo "\n==== Disk space used (Source/Build/Packages) ====\n"

cd ${BUILDAREA}
/usr/bin/du -s -k usr proto packages

#
# Copy packages into /pkgs location 
#
if [ "${PKGCPFLAG}" = "y" ]; then
	echo "\n==== Copying newly built packages into /pkgs ====\n"
	mkdir -p /pkgs
	cp -rf $PKGARCHIVE/* /pkgs
fi
