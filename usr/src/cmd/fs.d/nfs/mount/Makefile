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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014, Joyent, Inc. All rights reserved.
#
# cmd/fs.d/nfs/mount/Makefile

FSTYPE=		nfs
LIBPROG=	mount

include		../../Makefile.fstype

COMMON= $(FSLIB) nfs_sec.o replica.o nfs_subr.o selfcheck.o smfcfg.o
OBJS=	$(LIBPROG).o $(COMMON) webnfs_client.o webnfs_xdr.o
SRCS=	$(LIBPROG).c $(FSLIBSRC) ../lib/nfs_sec.c ../lib/replica.c \
	../lib/nfs_subr.c webnfs_xdr.c webnfs_client.c ../lib/selfcheck.c \
	../lib/smfcfg.c

UNCHECKED_HDRS=	webnfs.h

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-address
CERRWARN += -_gcc=-Wno-unused-function

#
# Message catalog
#
POFILE= mount.po

LDLIBS += -lrpcsvc -lnsl -lsocket -lscf
CPPFLAGS += -I. -I../.. -I../lib
CFLAGS += $(CCVERBOSE)

nfs_sec.o :=	CPPFLAGS += -DWNFS_SEC_NEGO

ROOTETCPROG	= $(LIBPROG:%=$(ROOTETCFSTYPE)/%)
CLOBBERFILES	+= $(LIBPROG)

.KEEP_STATE:

all:	$(LIBPROG)

$(LIBPROG):	webnfs.h $(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

nfs_sec.o:	../lib/nfs_sec.c
		$(COMPILE.c) ../lib/nfs_sec.c

replica.o:	../lib/replica.c
		$(COMPILE.c) ../lib/replica.c

nfs_subr.o:	../lib/nfs_subr.c
		$(COMPILE.c) ../lib/nfs_subr.c

selfcheck.o:	../lib/selfcheck.c
		$(COMPILE.c) ../lib/selfcheck.c

nfs_tbind.o:	../lib/nfs_tbind.c
		$(COMPILE.c) ../lib/nfs_tbind.c

smfcfg.o:	../lib/smfcfg.c
		$(COMPILE.c) ../lib/smfcfg.c

webnfs_xdr.c:	webnfs.x
	$(RPCGEN) -M -C -c -o $@ webnfs.x

webnfs_client.c:	webnfs.x
	$(RPCGEN) -M -C -l -o $@ webnfs.x

webnfs.h:	webnfs.x
	$(RPCGEN) -M -C -h -o $@ webnfs.x

webnfs.x:	../lib/webnfs.x
		$(RM) webnfs.x
		cp ../lib/webnfs.x .

#
# message catalog
#
catalog: $(POFILE)

$(POFILE): $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT)     $(XGETFLAGS) $(POFILE).i
	sed "/^domain/d"        messages.po     > $@
	$(RM) $(POFILE).i messages.po

install: all $(FSTYPEPROG)
	$(RM) $(ROOTETCPROG)
	$(SYMLINK) ../../../usr/lib/fs/$(FSTYPE)/$(LIBPROG) $(ROOTETCPROG)

lint:	webnfs.h webnfs_xdr.c webnfs_client.c lint_SRCS

clean:
	$(RM) $(OBJS) webnfs.x webnfs.h webnfs_xdr.c webnfs_client.c
