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
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		ufs
LIBPROG=	quota
ATTMK=		$(LIBPROG)

OTHERINSTALL=	$(ROOTUSRSBIN)/$(LIBPROG)
LINKVALUE=	../lib/fs/$(FSTYPE)/$(LIBPROG)

include		../../Makefile.fstype

OBJS=		quota.o rquota_xdr.o replica.o
SRCS=		$(OBJS:%.o=%.c)
XFILE=		$(ROOT)/usr/include/rpcsvc/rquota.x
CPPFLAGS +=	-I $(ROOT)/usr/include/sys -D_LARGEFILE64_SOURCE
LDLIBS +=		-lnsl

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-parentheses

# not linted
SMATCH=off

FILEMODE= 04555

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(OBJS) rquota_xdr.c

$(ROOTUSRSBIN)/$(LIBPROG):
		-$(RM) $@; $(SYMLINK) $(LINKVALUE) $@

rquota_xdr.c:	$(XFILE)
		$(RPCGEN) -c $(XFILE) -o $@

replica.o:	../../nfs/lib/replica.c
		$(COMPILE.c) ../../nfs/lib/replica.c
