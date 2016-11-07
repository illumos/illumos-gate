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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

include $(SRC)/tools/Makefile.tools

install all: softcore.c

SOFTCORE=	$(SRC)/common/ficl/softcore
PROG =	makesoftcore

#
# not needed: file access
#
FR = softcore.fr ifbrack.fr prefix.fr ficl.fr jhlocal.fr marker.fr
FR += freebsd.fr ficllocal.fr oo.fr classes.fr string.fr wordsets.fr
SOURCES=	$(FR:%=$(SOFTCORE)/%)

OBJS=	makesoftcore.o lz4.o
SRCS=	makesoftcore.c lz4.c
LDLIBS= -lumem

CPPFLAGS += -I.. -I$(SRC)/common/ficl

softcore.c: $(PROG) $(SOURCES)
	./$(PROG) $(SOURCES)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)

%.o: $(SOFTCORE)/%.c
	$(COMPILE.c) $<

clobber clean:
	$(RM) softcore.c $(OBJS) $(PROG)
