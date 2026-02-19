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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
#
# cmd/lp/cmd/lpsched/lpsched/Makefile
#

PROG=		lpsched

include		../../Makefile.lp
include		$(SRC)/cmd/Makefile.ctf

MANIFEST=	server.xml
SVCMETHOD=	print-svc

ROOTMANIFESTDIR=	$(ROOTSVCAPPLICATIONPRINT)

PURIFYOPTS      = -logfile=/tmp/errs.%p
PURIFY          = purify $(PURIFYOPTS)


# Doing -DDEBUG allows some nice log files to be generated
# with the -d option.

CPPFLAGS =	-I. -I$(LPINC) $(CPPFLAGS.master)

HDRS=				\
		nodes.h		\
		dispatch.h	\
		validate.h	\
		lpsched.h

SRCS=				\
		alerts.c	\
		cancel.c	\
		daisyforms.c	\
		disena.c	\
		disp1.c		\
		disp2.c		\
		disp3.c		\
		disp4.c		\
		disp5.c		\
		disptab.c	\
		dowait.c	\
		exec.c		\
		faults.c	\
		files.c		\
		flt.c		\
		fncs.c		\
		getkey.c	\
		init.c		\
		log.c		\
		lpfsck.c	\
		lpsched.c	\
		msgs.c		\
		notify.c	\
		pickfilter.c	\
		ports.c		\
		requeue.c	\
		rstatus.c	\
		schedule.c	\
		status.c	\
		terminate.c	\
		validate.c

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
		$(LIBSEC)

SYSLIBS=	-lcurses -lgen -lcurses -lnsl -ltsol -lsecdb -lbsm

LDLIBS +=	$(LPLIBS) $(SYSLIBS) $(LDSTACKPROTECT)

POFILE=		lp_cmd_lpsched.po

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS) $(LPLIBS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(PROG).pure:	$(OBJS) $(LPLIBS)
		$(PURIFY) $(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTLIBLPLOCLPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)


check:	$(CHKMANIFEST)


clean:
		$(RM) $(OBJS)

strip:
		$(STRIP) $(PROG)

lint:		lint_SRCS

include		../Makefile.msg

FRC:

include		../../../Makefile.targ
