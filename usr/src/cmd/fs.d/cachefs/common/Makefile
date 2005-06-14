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
# Copyright 1989,1996-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/fs.d/cachefs/common
#

FSTYPE=		cachefs

include		../../Makefile.fstype

PROGOBJS=	objs/subr.o objs/stats_create.o objs/stats_stats.o \
		objs/stats_log.o objs/stats_dbm.o objs/cachefsd_clnt.o \
		objs/cachefsd_xdr.o

PROGOBJSMT=	objsmt/subr.o objsmt/stats_create.o objsmt/stats_stats.o \
		objsmt/stats_log.o objsmt/stats_dbm.o objsmt/cachefsd_clnt.o \
		objsmt/cachefsd_xdr.o

include		../Makefile.cachefs

ARFLAGS=	rc
CLEANFILES +=	cachefsd_clnt.c cachefsd_xdr.c $(PROGOBJS) $(PROGOBJSMT)
CLOBBERFILES += $(LIBRARY) $(LIBRARYMT) cachefsd.h
RPCGENFLAGS=	-M -C -T
CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CPPFLAGSMT +=	${CPPFLAGS} -D_REENTRANT

all:	$(LIBRARY) $(LIBRARYMT)


 objs objsmt:
	-@mkdir -p $@

 objs/%.o : %.c
	$(CC) ${CFLAGS} ${CPPFLAGS} -c -o $@ $<
 
 objsmt/%.o : %.c
	$(CC) ${CFLAGS} ${CPPFLAGSMT} -c -o $@ $<


$(LIBRARY):	objs cachefsd.h $(PROGOBJS) 
	-$(RM) $(LIBRARY)
	$(AR) $(ARFLAGS) $(LIBRARY) $(PROGOBJS)
 
$(LIBRARYMT):	objsmt cachefsd.h $(PROGOBJSMT)
	-$(RM) $(LIBRARYMT)
	$(AR) $(ARFLAGS) $(LIBRARYMT) $(PROGOBJSMT)

cachefsd_clnt.c : cachefsd.x
	$(RPCGEN) $(RPCGENFLAGS) -l -o cachefsd_clnt.c cachefsd.x

cachefsd_xdr.c : cachefsd.x
	$(RPCGEN) $(RPCGENFLAGS) -c -o cachefsd_xdr.c cachefsd.x

cachefsd.h : cachefsd.x
	$(RPCGEN) $(RPCGENFLAGS) -h -o cachefsd.h cachefsd.x

