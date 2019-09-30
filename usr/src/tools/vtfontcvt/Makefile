#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2017 Toomas Soome <tsoome@me.com>
# Copyright 2019 Joyent, Inc.
#

CMDDIR=		$(SRC)/cmd/vtfontcvt

include		../Makefile.tools
include		$(CMDDIR)/Makefile.common

CPPFLAGS	+= -I../../uts/common
.KEEP_STATE:

all:		$(PROG)

install:	all .WAIT $(ROOTONBLDMACHPROG)

clean:
		$(RM) $(PROG) $(OBJS)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

#
# In order to build on older platforms, we specifically use the
# source-tree version of queue.h. When building as part of
# $SRC/cmd, we'll be using the $PROTO copy of queue.h anyway,
# so this is a $SRC/tools workaround only.
#
%.o:		$(CMDDIR)/%.c
		$(COMPILE.c) -I$(SRC)/uts/common -o $@ $<

include		../Makefile.targ
