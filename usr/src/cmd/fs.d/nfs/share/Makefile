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
#ident	"%Z%%M%	%I%	%E% SMI"
#
#
# Copyright 1993-1999,2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

FSTYPE=		nfs
LIBPROG=	share
ATTMK=		$(LIBPROG)

COMMON=		nfs_sec.o sharetab.o nfslog_config.o nfslogtab.o
LOCAL=		$(LIBPROG).o issubdir.o
OBJS=		$(LOCAL) $(COMMON)
SRCS=		$(LOCAL:%.o=%.c) $(COMMON:%.o=../lib/%.c)
OTHERINSTALL=	$(ROOTETC)/dfs/fstypes

#
# Message catalog
#
POFILE= share.po


catalog: $(POFILE)

$(POFILE): $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	sed "/^domain/d"        messages.po     > $@
	$(RM) $(POFILE).i messages.po

include		../../Makefile.fstype

LDLIBS +=	-lnsl
#
# uncomment to test vol fh
#
#CFLAGS +=	-DVOLATILE_FH_TEST

$(ROOTETC)/dfs/fstypes :=	FILEMODE= 644
$(ROOTETC)/dfs/fstypes :=	OWNER= root
$(ROOTETC)/dfs/fstypes :=	GROUP= root

$(ROOTETC)/dfs/%: %
	$(INS.file)

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

nfs_sec.o:	../lib/nfs_sec.c
		$(COMPILE.c) ../lib/nfs_sec.c

sharetab.o:	../lib/sharetab.c
		$(COMPILE.c) ../lib/sharetab.c

nfslog_config.o:	../lib/nfslog_config.c
		$(COMPILE.c) ../lib/nfslog_config.c

nfslogtab.o:	../lib/nfslogtab.c
		$(COMPILE.c) ../lib/nfslogtab.c

lint:	lint_SRCS

clean:     
	$(RM) $(OBJS)
