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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# Object lists are organized into primary (most frequently used code) and
# secondary lists (less frequently used code, ie. profiling support).

P_COMOBJS=	debugdata.o \
		analyze.o	elf.o		globals.o	malloc.o \
		mutex.o		paths.o		setup.o		util.o \
		dlfcns.o	config_elf.o	locale.o	tsort.o \
		getcwd.o	remove.o	sunwmove.o	tls.o \
		cap.o

S_COMOBJS=	debug.o		audit.o		object.o

G_MACHOBJS=	doreloc.o

P_MACHOBJS=	i386_elf.o	_setup.o	zero.o

CP_MACHOBJS=	dtrace_data.o

S_MACHOBJS=

P_ASOBJS=	boot.o		boot_elf.o	caller.o

S_ASOBJS=

CRTSRCS=	../../../../lib/common/i386
CRTI=		pics/crti.o
CRTN=		pics/crtn.o
CRTS=		$(CRTI)		$(CRTN)

BASEPLAT=	i386

# __GNUC is overridden in the environment when building with gcc
__GNUC:sh=		echo \\043

# We build 32-bit objects with cc by default
MAPFILE-ORDER =		../common/mapfile-order-devpro
$(__GNUC)MAPFILE-ORDER =	../common/mapfile-order-gcc

include		$(SRC)/cmd/sgs/rtld/Makefile.com

# Add any machine specific flags.

CPPFLAGS +=	-I../../../../uts/$(PLAT)/krtld
ADBGENCFLAGS +=	-erroff=%all
ADBGENFLAGS +=	-milp32
ADBSUB=		$(ADBSUB32)
SONAME=		$(VAR_RTLD_SONAME)

SGSMSGTARG +=	$(SGSMSGINTEL) $(SGSMSGINTEL32) $(SGSMSG32)

.KEEP_STATE:

all:		$(RTLD)

install:	all $(ROOTDYNLIB) $(VAR_RTLD_ETCDYNLIB)

lint:		$(LINTOUT32)

adbmacros:	adb .WAIT $(ADBSCRIPTS)

adbinstall:	adbmacros .WAIT $(ROOTADB)

pics/%.o:       $(SRCBASE)/uts/$(PLAT)/krtld/%.c
		$(COMPILE.c) -o $@ $<  $(WARNFLAGS)
		$(POST_PROCESS_O)

include		$(SRC)/cmd/sgs/rtld/Makefile.targ
