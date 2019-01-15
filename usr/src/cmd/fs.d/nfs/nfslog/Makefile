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
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		nfs
TYPEPROG=	nfslogd
ATTMK=		$(TYPEPROG)
DEFAULTFILES=	nfslogd.dfl

include		../../Makefile.fstype

COMMON=		nfslog_config.o nfslogtab.o
LOCAL=		process_buffer.o fhtab.o nfslogd.o nfslog_elf.o \
		nfslog_trans.o nfslog_ipaddr.o readbuf.o dbtab.o \
		nfs_log_xdr.o buffer_list.o
OBJS=		$(LOCAL) $(COMMON)
SRCS=		$(LOCAL:%.o=%.c) $(COMMON:%.o=../lib/%.c)
LDLIBS +=	-lsocket -lnsl
CFLAGS += 	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-type-limits

# not linted
SMATCH=off

CPPFLAGS += 	-D_FILE_OFFSET_BITS=64

#
# Message catalog
#
POFILE= nfslog.po

catalog:        $(POFILE)

$(POFILE):      $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS)   > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	sed "/^domain/d"        messages.po     > $@
	$(RM) messages.po $(POFILE).i

$(TYPEPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTETCDEFAULTFILES)

nfslog_config.o:	../lib/nfslog_config.c
		$(COMPILE.c) ../lib/nfslog_config.c

nfslogtab.o:	../lib/nfslogtab.c
		$(COMPILE.c) ../lib/nfslogtab.c

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

clean:     
	$(RM) $(OBJS)
