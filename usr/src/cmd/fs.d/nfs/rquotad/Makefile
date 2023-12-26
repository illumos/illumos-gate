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
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		nfs
TYPEPROG=	rquotad
ATTMK=		$(TYPEPROG)

include ../../Makefile.fstype

OBJS=	rpc.rquotad.o rquota_xdr.o
SRCS=	$(OBJS:%.o=%.c)
XFILE=	$(ROOT)/usr/include/rpcsvc/rquota.x

CPPFLAGS += -D_LARGEFILE64_SOURCE
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable
LDLIBS += -lnsl

# unknown type for func
SMATCH=off

$(TYPEPROG):	$(OBJS)
		$(LINK.c) -o $@ $(LDLIBS) $(OBJS)
		$(POST_PROCESS)

clean:
		$(RM) $(OBJS) rquota_xdr.c

rquota_xdr.c:	$(XFILE)
		$(RPCGEN) -c $(XFILE) -o $@
