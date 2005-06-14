#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

COMMONOBJS=	plugin_common.o
OBJECTS=	$(PLUG_OBJS) $(COMMONOBJS)

include $(SRC)/lib/Makefile.lib

CPPFLAGS +=	-I$(SRC)/lib/libsasl/include

LIBS =		$(DYNLIB)
SRCS=		$(PLUG_OBJS:%.o=../%.c) $(COMMONOBJS:%.o=../../%.c)
LDLIBS +=	-lsocket -lc $(PLUG_LIBS)
SRCDIR=		..

MAPDIR= 	../spec/$(TRANSMACH)
SPECMAPFILE=	$(MAPDIR)/mapfile

ROOTLIBDIR=	$(ROOT)/usr/lib/sasl
ROOTLIBDIR64=	$(ROOT)/usr/lib/sasl/$(MACH64)

LINTFLAGS=	$(ENC_FLAGS)
LINTFLAGS64=	-Xarch=$(MACH64:sparcv9=v9) $(ENC_FLAGS)

CFLAGS +=	$(CCVERBOSE) $(XSTRCONST) $(ENC_FLAGS)
CFLAGS64 +=	$(XSTRCONST) $(ENC_FLAGS)

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

pics/%.o: $(SRC)/lib/libsasl/plugin/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/Makefile.targ
