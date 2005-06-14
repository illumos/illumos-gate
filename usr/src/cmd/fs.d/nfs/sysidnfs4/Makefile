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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.
# All rights reserved.  Use is subject to license terms.
#
PROG	 =	sysidnfs4
POFILE	 =	$(PROG:%=%.po)
SRCS	 =	sysidnfs4.c config_nfs4.c
HDRS	+=	$(SRCS:%.c=%.h)
OBJS	 =	$(SRCS:%.c=%.o)
DEFINES	 =
CFLAGS	+=	-O $(DEFINES)
CPPFLAGS+=
LDLIBS	+=

include ../../../Makefile.cmd

catalog:	$(POFILE)

$(POFILE):	$(SRCS)
		$(RM) $@
		$(COMPILE.cpp) $(SRCS) > $(POFILE).i
		$(XGETTEXT) $(XGETFLAGS) $(POFILE).i
		sed "/^domain/d" messages.po > $@
		$(RM) $(POFILE).i messages.po

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

$(OBJS):	$(HDRS)

$(ROOTUSRSBINPROG) :=	OWNER= root
$(ROOTUSRSBINPROG) :=	GROUP= sys
$(ROOTUSRSBINPROG) :=	FILEMODE= 555

CLOBBERFILES += $(ROOTUSRSBINPROG)

all:		$(PROG)

clean:
		$(RM) $(OBJS) $(POFILE) $(PROG)

lint:		$(SRCS) lint_SRCS

install:	$(ROOTUSRSBINPROG)

include ../../../Makefile.targ
