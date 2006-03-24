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
# cmd/lp/cmd/Makefile
#

include 	../Makefile.lp

OWNER = root

SUBDIRS =	lpc lptest lpadmin lpsched lpstat adaptor scripts

LOCALPROG1 =	lp lpsystem lpmove lpshut
LOCALPROG2 =	accept 
LOCALPROG =	$(LOCALPROG1) $(LOCALPROG2)
LOCALLINKS =	disable enable reject

SBINPROG =	lpfilter lpforms lpusers

LIBLINKS =	$(SBINPROG)

PROG =		$(LOCALPROG) $(SBINPROG) 

COMMONOBJ=	comb.o
OTHEROBJS=	cancel.o lp.o $(SBINPROG:=.o)

OBJS=		$(COMMONOBJ) $(OTHEROBJS)

SRCS=          $(OBJS:.o=.c)

POFILE=		lp_cmd.po
POFILES=	$(SRCS:%.c=%.po) lpsystem.po lpmove.po lpschedlpshut.po

ROOTLIBLPLOCLPROG=	$(LOCALPROG:%=$(ROOTLIBLPLOCL)/%)
ROOTSBINPROG=	$(SBINPROG:%=$(ROOTUSRSBIN)/%)
ROOTSYMLINKS=	$(LIBLINKS:%=$(ROOTLIB)/%)
ROOTSYMLINKS2=	$(LOCALLINKS:%=$(ROOTLIBLPLOCL)/%)


CPPFLAGS =	-I$(LPINC) $(CPPFLAGS.master)

# conditional assignments
#
accept:=	LDLIBS += $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBLP)
cancel:=	LDLIBS += $(LIBREQ) $(LIBMSG) $(LIBOAM) $(LIBLP)
lp:=		LDLIBS += $(LIBPRT) $(LIBREQ) $(LIBMSG) $(LIBOAM) $(LIBLP)
lpfilter:=	LDLIBS += $(LIBFLT) $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBLP) \
			-lgen -z lazyload -lsecdb -z nolazyload
lpforms:=	LDLIBS += $(LIBFRM) $(LIBMSG) $(LIBREQ) $(LIBOAM) \
			$(LIBACC) $(LIBLP) \
			-z lazyload -lsecdb -z nolazyload
lpmove:=	LDLIBS += $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBLP)
lpshut:=	LDLIBS += $(LIBMSG) $(LIBOAM) $(LIBLP)
lpsystem:=	LDLIBS += $(LIBSYS) $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBLP) \
			-lnsl -z lazyload -lsecdb -z nolazyload
lpusers:=	LDLIBS += $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBUSR) $(LIBLP)

.KEEP_STATE:

all:		$(PROG) $(SUBDIRS)

accept:		$(COMMONOBJ)
		$(LINK.c) -o $@ $(COMMONOBJ) $(LDFLAGS) $(LDLIBS)
		$(POST_PROCESS)


install:	$(PROG) $(ROOTLIBLPLOCLPROG) $(ROOTSBINPROG) \
		$(ROOTSYMLINKS) $(ROOTSYMLINKS2) $(SUBDIRS) 

catalog:	$(SUBDIRS) $(POFILE)
		$(CP) $(POFILE) ..

clean:		$(SUBDIRS)
		$(RM) $(OBJS)

clobber:	$(SUBDIRS) local_clobber

local_clobber:
		$(RM) $(OBJS) $(PROG) lpmove.o lpsystem.o $(CLOBBERFILES)

strip:		$(SUBDIRS)
		$(STRIP) $(PROG)

lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

$(LOCALPROG1) $(SBINPROG): $$@.o
		$(LINK.c) -o $@ $@.o $(LDFLAGS) $(LDLIBS)
		$(POST_PROCESS)

$(ROOTSYMLINKS):
		$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@

$(ROOTSYMLINKS2):
		$(RM) $@; $(SYMLINK) ./accept $@

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

include		../Makefile.lp.msg

FRC:
