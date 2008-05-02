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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include 	../Makefile.lp

OWNER = root

SUBDIRS =	lptest lpadmin lpsched scripts

LOCALPROG =	lpshut

SBINPROG =	lpfilter lpforms lpusers

LIBLINKS =	$(SBINPROG)

PROG =		$(LOCALPROG) $(SBINPROG) 

OBJS=	$(SBINPROG:=.o)

SRCS=          $(OBJS:.o=.c)

POFILE=		lp_cmd.po
POFILES=	$(SRCS:%.c=%.po) lpschedlpshut.po

ROOTLIBLPLOCLPROG=	$(LOCALPROG:%=$(ROOTLIBLPLOCL)/%)
ROOTSBINPROG=	$(SBINPROG:%=$(ROOTUSRSBIN)/%)
ROOTSYMLINKS=	$(LIBLINKS:%=$(ROOTLIB)/%)


CPPFLAGS =	-I$(LPINC) $(CPPFLAGS.master)
LDFLAGS +=	$(MAPFILE.NGB:%=-M%)

# conditional assignments
#
lpfilter:=	LDLIBS += $(LIBFLT) $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBLP) \
			-lgen -lsecdb
lpforms:=	LDLIBS += $(LIBFRM) $(LIBMSG) $(LIBREQ) $(LIBOAM) \
			$(LIBACC) $(LIBLP) -lsecdb
lpshut:=	LDLIBS += $(LIBMSG) $(LIBOAM) $(LIBLP)
lpusers:=	LDLIBS += $(LIBMSG) $(LIBACC) $(LIBOAM) $(LIBUSR) $(LIBLP)

.KEEP_STATE:

all:		$(PROG) $(SUBDIRS)

install:	$(PROG) $(ROOTLIBLPLOCLPROG) $(ROOTSBINPROG) \
		$(ROOTSYMLINKS) $(SUBDIRS) 

catalog:	$(SUBDIRS) $(POFILE)
		$(CP) $(POFILE) ..

clean:		$(SUBDIRS)
		$(RM) $(OBJS)

clobber:	$(SUBDIRS) local_clobber

local_clobber:
		$(RM) $(OBJS) $(PROG) $(CLOBBERFILES)

strip:		$(SUBDIRS)
		$(STRIP) $(PROG)

lint:
		$(LINT.c) $(SRCS) $(LDLIBS)

$(ROOTSYMLINKS):
		$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

include		../Makefile.lp.msg

FRC:
