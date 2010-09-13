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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/cmd/lpadmin/Makefile
#

include		../../Makefile.lp

CPPFLAGS =	-D_REENTRANT -I. -I$(LPINC) $(CPPFLAGS.master)

SRCS=		chkopts.c	\
		default.c	\
		do_align.c	\
		do_fault.c	\
		do_mount.c	\
		do_printer.c	\
		do_pwheel.c	\
		done.c		\
		fromclass.c	\
		ismodel.c	\
		lpadmin.c	\
		options.c	\
		output.c	\
		pick_opts.c	\
		rmdest.c	\
		send_message.c	\
		signals.c	\
		startup.c	\
		usage.c

OBJS=		$(SRCS:.c=.o)

LPLIBS=		$(LIBACC)	\
		$(LIBCLS)	\
		$(LIBMSG)	\
		$(LIBPRT)	\
		$(LIBFRM)	\
		$(LIBREQ)	\
		$(LIBOAM)	\
		$(LIBLP)

SYSLIBS=	-lcurses

LDLIBS +=	-lsecdb $(LPLIBS) $(SYSLIBS) $(I18N)
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

PROG=		lpadmin


#ROOTSYMLINK=	$(ROOTLIBPROG)

POFILE=		lp_cmd_lpadmin.po

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS) $(MAPFILE.NGB)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTLIBLPLOCLPROG) #$(ROOTSYMLINK)

#$(ROOTSYMLINK):
#		$(RM) $@; $(SYMLINK) ../sbin/$(PROG) $@

clean:
		$(RM) $(OBJS)

clobber: clean
		-$(RM) $(PROG) $(CLOBBERFILES)

strip:
		$(STRIP) $(PROG)

lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

include		../Makefile.msg
