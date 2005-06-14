#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 1998-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
# Script to build the MDB modules present in a workspace against the set of
# include files saved in an MDB "root" (created with mkroot.sh), and install
# resulting modules into this tree so that it can be used as the argument
# to ``mdb -R'' or by mdb's auto-detect code, used by the mdb.sh wrapper.
# We use the ``make dmods'' target to do the build -- this is equivalent to
# make install, but does not build the debugger itself, and pass a special
# define (_MDB_BLDID) into the compilation environment so that the module
# source can detect the various changes in header files, etc.  This is only
# used for module source kept on mdb.eng that needs to compile against
# legacy builds of the operating system.
#

PNAME=`basename $0`
opt_R=false
umask 022

if [ $# -ne 0 -a "x$1" = x-R ]; then
	opt_R=true
	shift
fi

if [ $# -ne 1 -o -z "${INCROOT:=$1}" -o ! -d "$INCROOT" ]; then
	echo "Usage: $PNAME [-R] root-dir"
	exit 2
fi

if $opt_R; then
	ROOT="$INCROOT"
	export ROOT
fi

if [ -z "$SRC" -a -z "$CODEMGR_WS" ]; then
	echo "$PNAME: \$SRC or \$CODEMGR_WS must be set" >& 2
	exit 1
fi

if [ -z "$ROOT" ]; then
	echo "$PNAME: \$ROOT must be set" >& 2
	exit 1
fi

if [ -z "$SRC" ]; then
	SRC="$CODEMGR_WS/usr/src"
	export SRC
fi

#
# Derive a build-id based on the name of the $ROOT directory.  The build-id
# is passed into the compilation environment as _MDB_BLDID, and consists of
# a 4-digit hexadecimal number whose first two digits are the release number
# (e.g. 0x27XX for Solaris 2.7) and whose last two digits are the build number.
#
case "`basename $INCROOT`" in
s297_fcs) BLDID=0x2637 ;;
s998_fcs) BLDID=0x2721 ;;
 s28_fcs) BLDID=0x2838 ;;
  s399_*) BLDID=0x27FF ;;
  s599_*) BLDID=0x27FF ;;
  s899_*) BLDID=0x27FF ;;
 s1199_*) BLDID=0x27FF ;;
   s81_*) BLDID=0x81`basename $INCROOT | sed 's/s81_//' | tr -cd '[0-9]'` ;;
       *) echo "$PNAME: cannot derive _MDB_BLDID for $INCROOT" >& 2; exit 1 ;;
esac

#
# Set up the necessary environment variables to perform a build.  Basically
# we need to do the same stuff as bld_env or bfmenv.
#
[ `id | cut -d'(' -f1` != 'uid=0' ] && CH='#' || CH=; export CH
VERSION=${VERSION:-"`basename $INCROOT`:`date '+%m/%d/%y'`"}; export VERSION
MACH=`uname -p`; export MACH
TMPDIR=/tmp; export TMPDIR
NODENAME=`uname -n`; export NODENAME
PATH="$PUBLIC/bin:$PUBLIC/bin/$MACH:/opt/onbld/bin:/opt/onbld/bin/$MACH:/opt/SUNWspro/bin:/opt/teamware/ParallelMake/bin:/usr/ccs/bin:/usr/bin:/usr/sbin:/usr/openwin/bin:."; export PATH
INS=/opt/onbld/bin/$MACH/install.bin; export INS
MAKEFLAGS=e; export MAKEFLAGS

#
# We need to export $BLDID into the compilation environment, and make sure
# to remap the default include path from /usr/include to $INCROOT/usr/include.
#
ENVCPPFLAGS1="-YI,$INCROOT/usr/include"; export ENVCPPFLAGS1
ENVCPPFLAGS2="-D_MDB_BLDID=$BLDID"; export ENVCPPFLAGS2
ENVCPPFLAGS3=; export ENVCPPFLAGS3
ENVCPPFLAGS4=; export ENVCPPFLAGS4

ENVLDLIBS1=; export ENVLDLIBS1
ENVLDLIBS2=; export ENVLDLIBS2
ENVLDLIBS3=; export ENVLDLIBS3

cd $SRC && make clobber && make dmods
