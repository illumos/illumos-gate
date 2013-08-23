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
#
# cmd/fs.d/cachefs/cfsd
#

FSTYPE=		cachefs
LIBPROG_C=	cachefsd
ATTMK=		$(LIBPROG_C)
LINKVALUE=      ../lib/fs/$(FSTYPE)/$(LIBPROG_C)

include		../../Makefile.fstype

PROGOBJS =	cfsd_main.o cfsd_svc.o cfsd_kmod.o cfsd_maptbl.o \
		cfsd_logelem.o cfsd_cache.o cfsd_fscache.o cfsd_all.o \
		cfsd_logfile.o cfsd_subr.o

LDLIBSMT =	$(LDLIBS.cmd) $(CFSLIBMT) $(MDBUGLIB) -lnsl
include		../Makefile.cachefs

MDBUGLIB=	../mdbug/libdbug.a
CPPFLAGS +=	-I.. -D_REENTRANT
RPCGENFLAGS=	-M -C -T
CLOBBERFILES +=	$(LIBPROG_C) cachefsd_tbl.i

all : $(LIBPROG_C)

install : $(ROOTLIBFSTYPE)/$(LIBPROG_C)

$(LIBPROG_C):	$(OBJS)
		$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBSMT)
		$(POST_PROCESS)

testmap : cfsd_maptbl.o testmap.o
		$(LINK.c) -o $@ cfsd_maptbl.o testmap.o $(LDLIBS)

cachefsd_tbl.i :	$(CACHEFSDIR)/cachefsd.x
		$(RPCGEN) $(RPCGENFLAGS) -t -o cachefsd_tbl.i \
			$(CACHEFSDIR)/cachefsd.x

cfsd_main.o :	cfsd_main.c cachefsd_tbl.i

clobber :	templates

templates :
		rm -rf SunWS_cache

$(LIBPROG_C) :	$(CFSLIB) $(MDBUGLIB)

$(MDBUGLIB) :
		cd $(@D); pwd; $(MAKE) $(TARGET);
		@pwd

$(PROGOBJS) :	$(CACHEFSDIR)/cachefsd.h ../mdbug/mdbug.h
