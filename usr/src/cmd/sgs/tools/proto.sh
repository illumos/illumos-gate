#!/bin/sh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Generate a proto area suitable for the current architecture ($(MACH))
# sufficient to support the sgs build.
#
# Currently, the following releases are supported:
#	5.11, 5.10, and 5.9.
#

if [ "X$CODEMGR_WS" = "X" -o "X$MACH" = "X" ] ; then
	echo "usage: CODEMGR_WS and MACH environment variables must be set"
	exit 1
fi

RELEASE=$1

if [ "X$RELEASE" = "X" ] ; then
	echo "usage: proto release"
	exit 1;
fi

IS_THIS_UNIFIED=1

case $RELEASE in
	"5.11") break;;
	"5.10") break;;
	"5.9") IS_THIS_UNIFIED=0;  break;;
	*)
	echo "usage: unsupported release $RELEASE specified"
	exit 1;;
esac

dirs="	$CODEMGR_WS/proto \
	$CODEMGR_WS/proto/root_$MACH \
	$CODEMGR_WS/proto/root_$MACH/lib \
	$CODEMGR_WS/proto/root_$MACH/usr \
	$CODEMGR_WS/proto/root_$MACH/usr/demo \
	$CODEMGR_WS/proto/root_$MACH/usr/lib \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/abi \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/link_audit \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/mdb \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/mdb/proc \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/pics \
	$CODEMGR_WS/proto/root_$MACH/usr/4lib \
	$CODEMGR_WS/proto/root_$MACH/usr/bin \
	$CODEMGR_WS/proto/root_$MACH/usr/ccs \
	$CODEMGR_WS/proto/root_$MACH/usr/ccs/bin \
	$CODEMGR_WS/proto/root_$MACH/usr/include \
	$CODEMGR_WS/proto/root_$MACH/usr/include/sys \
	$CODEMGR_WS/proto/root_$MACH/usr/xpg4 \
	$CODEMGR_WS/proto/root_$MACH/usr/xpg4/bin \
	$CODEMGR_WS/proto/root_$MACH/etc \
	$CODEMGR_WS/proto/root_$MACH/etc/lib \
	$CODEMGR_WS/proto/root_$MACH/opt \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/bin \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/doc \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/lib \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/man \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/man/man1 \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/man/man1l \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/man/man3t \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/man/man3l \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/man/man3x"

#
# Add 64bit directories
#
MACH64=""
if [ $MACH = "sparc" ]; then
    MACH64="sparcv9";
fi
if [ $MACH = "i386" ]; then
    MACH64="amd64";
fi
if [ "${MACH64}x" != x ]; then

	dirs="$dirs \
	$CODEMGR_WS/proto/root_$MACH/lib/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/bin/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/ccs/bin/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/abi/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/link_audit/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/mdb/proc/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/usr/lib/pics/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/bin/$MACH64 \
	$CODEMGR_WS/proto/root_$MACH/opt/SUNWonld/lib/$MACH64 \
	"
fi

for dir in `echo $dirs`
do
	if [ ! -d $dir ] ; then
		echo $dir
		mkdir $dir
		chmod 777 $dir
	fi
done

# We need a local copy of libc_pic.a (we should get this from the parent
# workspace, but as we can't be sure how the proto area is constructed there
# simply take it from a stashed copy on the linkers server. If
# LINKERS_EXPORT is defined, we use it. Failing that, we fall over
#  to linkers.central.
if [ "$LINKERS_EXPORT" = "" ]; then
    LINKERS_EXPORT=/net/linkers.central/export
fi

if [ $MACH = "sparc" ]; then
	PLATS="sparc sparcv9"
elif [ $MACH = "i386" ]; then
	PLATS="i386 amd64"
else
	echo "Unknown Mach: $MACH - no libc_pic.a provided!"
	PLATS=""
fi

for p in $PLATS
do
	SRCLIBCDIR=${SRC}/lib/libc/$p
	if [ ! -d $SRCLIBCDIR ]; then
		mkdir -p $SRCLIBCDIR
	fi
	if [ ! -f $SRCLIBCDIR/libc_pic.a ]; then
		cp $LINKERS_EXPORT/big/libc_pic/$RELEASE/$p/libc_pic.a \
			$SRCLIBCDIR
	fi
done

SYSLIB=$CODEMGR_WS/proto/root_$MACH/lib
USRLIB=$CODEMGR_WS/proto/root_$MACH/usr/lib

if [ ! -h $USRLIB/ld.so.1 ]; then
	rm -f $USRLIB/ld.so.1
	ln -s ../../lib/ld.so.1 $USRLIB/ld.so.1
	echo "$USRLIB/ld.so.1 -> ../../lib/ld.so.1"
fi

#
# In addition create some 64 symlinks so that dependencies referenced
# from our test environment will map back to the appropriate libraries.
#
if [ ! -h $SYSLIB/64 ] ; then
	rm -f $SYSLIB/64
	ln -s $MACH64 $SYSLIB/64
	echo "$SYSLIB/64 -> $SYSLIB/$MACH64"
fi
if [ ! -h $USRLIB/64 ] ; then
	rm -f $USRLIB/64
	ln -s $MACH64 $USRLIB/64
	echo "$USRLIB/64 -> $USRLIB/$MACH64"
fi
if [ ! -h $USRLIB/link_audit/64 ] ; then
	rm -f $USRLIB/link_audit/64
	ln -s $MACH64 $USRLIB/link_audit/64
	echo "$USRLIB/link_audit/64 -> $USRLIB/link_audit/$MACH64"
fi
if [ ! -h $USRLIB/64/ld.so.1 ]; then
	rm -f $USRLIB/64/ld.so.1
	ln -s ../../../lib/64/ld.so.1 $USRLIB/64/ld.so.1
	echo "$USRLIB/64/ld.so.1 -> ../../../lib/64/ld.so.1"
fi

#
#
#
if [ $IS_THIS_UNIFIED = 0 ] ; then
	rm -fr $CODEMGR_WS/proto/root_$MACH/lib
	ln -s $CODEMGR_WS/proto/root_$MACH/usr/lib $CODEMGR_WS/proto/root_$MACH/lib
fi
