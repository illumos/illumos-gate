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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/lp/cmd/lpsched/lpsched/Makefile
#

PROG=		lpsched

include		../../Makefile.lp

MANIFEST=	server.xml

ROOTMANIFESTDIR=	$(ROOTSVCAPPLICATIONPRINT)
ROOTMETHOD=		$(ROOTLIBSVCMETHOD)/print-svc
$(ROOTMANIFEST)		:= FILEMODE= 444

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

SYSLIBS=	-lcurses -lgen -lcurses -lnsl

LDLIBS +=	$(LPLIBS) $(SYSLIBS)

LPSCHED_VERSION_STRING  = ($(ECHO) build info: \\\c; date +%D:%H:%M:%S)

POFILE=		lp_cmd_lpsched.po

.KEEP_STATE:

all:		$(PROG) 

$(PROG):	$(OBJS) $(LPLIBS) lpschedvers.o
		$(LINK.c) $(OBJS) lpschedvers.o -o $@ $(LDLIBS)
		$(POST_PROCESS)

lpschedvers.c:	FRC
	@-$(ECHO) "rebuilding lpschedvers.c"
	@-( \
	$(ECHO) "/*" ; \
	$(ECHO) " * This file is derived from cmd/lpsched/lpsched/Makefile" ; \
	$(ECHO) " */\n" ; \
	$(ECHO) "#pragma\tident\t\"@(#)lpschedvers.c\tDERIVED\t96/2/1 SMI\"\n" ; \
	$(ECHO) "char *lpsched_buildinfo = \"`$(LPSCHED_VERSION_STRING)`\\\\n\";" ; \
	$(ECHO) "" ) > ./lpschedvers.c

$(PROG).pure:	$(OBJS) $(LPLIBS)
		$(PURIFY) $(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTLIBLPLOCLPROG) $(ROOTMANIFEST) $(ROOTMETHOD)


check:	$(CHKMANIFEST)


clean:
		$(RM) $(OBJS)
		$(RM) lpschedvers.c lpschedvers.o

clobber:	clean
		-$(RM) $(PROG) $(CLOBBERFILES)

strip:
		$(STRIP) $(PROG)

lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

include		../Makefile.msg

FRC:
