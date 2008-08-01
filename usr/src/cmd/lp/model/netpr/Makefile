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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/model/netpr
#

PROG=		netpr

include		../../Makefile.lp

PURIFYOPTS      = -logfile=/tmp/errs.%p
PURIFY          = purify $(PURIFYOPTS)

CPPFLAGS =	-I. -I$(LPINC) 	\
		$(CPPFLAGS.master)

HDRS=				\
		netpr.h		\
		netdebug.h

SRCS=				\
		netpr.c		\
		misc.c		\
		net.c		\
		tcp_misc.c	\
		bsd_misc.c

OBJS=		$(SRCS:.c=.o)


LPLIBS =			\
		$(LIBMSG)	\
		$(LIBFRM)	\
		$(LIBREQ)	\
		$(LIBPRT)	\
		$(LIBCLS)	\
		$(LIBACC)	\
		$(LIBFLT)	\
		$(LIBUSR)	\
		$(LIBOAM)	\
		$(LIBLP)	\
		$(LIBSEC)	\
		$(LIBSYS)

SYSLIBS=	-lnsl -lsocket

LDLIBS +=	$(LPLIBS) $(SYSLIBS)
ROOTLIBLPBIN =	$(ROOTLIBLP)/bin

ROOTNETPRPROG =	$(PROG:%=$(ROOTLIBLPBIN)/%)

FILEMODE=	04511
OWNER=		root
GROUP=		bin

POFILE=		lp_model_netpr.po

.KEEP_STATE:

all:		$(PROG)

install:	all $(ROOTLIBLPBIN) $(ROOTNETPRPROG)

$(ROOTLIBLPBIN):
	$(INS.dir)

$(ROOTLIBLPBIN)/%:	%
	$(INS.file)


$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(PROG).pure:	$(OBJS)
		$(PURIFY) $(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(OBJS)

clobber:	clean
		-$(RM) $(PROG) $(CLOBBERFILES)

strip:
		$(STRIP) $(PROG)

cstyle:
		cstyle $(SRCS)

LINTFLAGS	+= -lnsl -lsocket
lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

include		../Makefile.msg
