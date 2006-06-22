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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/cmd/lpstat/Makefile
#

include 	../../Makefile.lp

PROG=		lpstat

SRCS =		accept.c	\
		add_mounted.c	\
		charset.c	\
		class.c		\
		device.c	\
		done.c		\
		form.c		\
		lpstat.c	\
		output.c	\
		parse.c		\
		printer.c	\
		request.c	\
		send_message.c

OBJS=		$(SRCS:.c=.o)


CPPFLAGS =	-I$(LPINC) $(CPPFLAGS.master)

LPLIBS =	$(LIBACC)	\
		$(LIBCLS)	\
		$(LIBMSG)	\
		$(LIBPRT)	\
		$(LIBFRM)	\
		$(LIBOAM)	\
		$(LIBLP)

SYSLIBS=	-lcurses

LDLIBS +=	$(LPLIBS) $(SYSLIBS) $(I18N) -z lazyload -lsecdb -z nolazyload

POFILE=		lp_cmd_lpstat.po

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTLIBLPLOCLPROG)

clean:
		$(RM) $(OBJS)

clobber:	clean
		-$(RM) $(PROG) $(CLOBBERFILES)

strip:
		$(STRIP) $(PROG)

lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

include		../Makefile.msg
