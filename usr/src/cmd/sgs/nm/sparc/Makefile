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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

PROG=		nm
XPG4PROG=	nm

ARFORMAT=	PORTAR

include		../../../Makefile.cmd
include		../../Makefile.com

COMOBJS=	nm.o

OBJS=		$(COMOBJS)
XPG4OBJS=	objs.xpg4/nm.o

SRCS=		$(COMOBJS:%.o=../common/%.c)

LLDFLAGS=	'-R$$ORIGIN/../../lib'
INCLIST=	-I../../include -I../../include/sparc \
		-I$(SRCBASE)/uts/$(ARCH)/sys
DEFLIST=	-DTARGET=SPARC -DSPARC=1 -D$(ARFORMAT) -DELF
CPPFLAGS=	$(INCLIST) $(DEFLIST) $(CPPFLAGS.master)  -I$(ELFCAP)
LDLIBS +=	$(CONVLIBDIR) $(CONV_LIB) $(ELFLIBDIR) -lelf
objs.xpg4/%.o := CPPFLAGS += -DXPG4


# Building SUNWonld results in a call to the `package' target.  Requirements
# needed to run this application on older releases are established:
#	i18n support requires libintl.so.1 prior to 2.6

package :=	LDLIBS += /usr/lib/libintl.so.1


objs.xpg4/%.o:	../common/%.c
		$(COMPILE.c) -o $@ $<

%.o:		../common/%.c
		$(COMPILE.c) $<

.KEEP_STATE:

all:		$(PROG) $(XPG4)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LLDFLAGS) $(LDLIBS)
		$(POST_PROCESS)

$(XPG4):	$(XPG4OBJS)
		$(LINK.c) $(XPG4OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(XPG4OBJS):	objs.xpg4

objs.xpg4:
	-@mkdir -p $@

package \
install:	all $(VAR_SGSBINPROG) $(ROOTXPG4PROG) $(VAR_SGSCCSLINK)

clean:
		$(RM) $(OBJS) $(XPG4OBJS) $(CLEANFILES)

include		../../../Makefile.targ
include		../../Makefile.targ
