#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#

PROG= mkctype
CATEGORY=LC_CTYPE

include ../Makefile.common

CPPFLAGS += -I$(SRC)/lib/libc/port/locale -D_FILE_OFFSET_BITS=64
YFLAGS	= -d -b mkctype_yacc
LFLAGS	= -t

OBJS = $(MACH)/mkctype_lex.o $(MACH)/mkctype_yacc.tab.o
HDRS = ldef.h extern.h
CLEANFILES =	mkctype_yacc.tab.c mkctype_yacc.tab.h mkctype_lex.c

en_COMMON =	en_AU en_CA en_GB en_NZ en_US

ASCII =		$(en_COMMON:%=%.US-ASCII)

LATIN1 =	$(en_COMMON:%=%.ISO8859-1)

LATIN15 =	$(en_COMMON:%=%.ISO8859-15)

UTF8 =		$(en_COMMON:%=%.UTF-8) en_IE.UTF-8

.KEEP_STATE:

all: $(MACH)/$(PROG) $(MACHLOCALES)

$(MACH)/$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ASCII:%=$(MACH)/%):	$(MACH)/US-ASCII
	$(RM) $@
	$(LN) $(MACH)/US-ASCII $@

$(LATIN1:%=$(MACH)/%):	$(MACH)/ISO8859-1
	$(RM) $@
	$(LN) $(MACH)/ISO8859-1 $@

$(LATIN15:%=$(MACH)/%):	$(MACH)/ISO8859-15
	$(RM) $@
	$(LN) $(MACH)/ISO8859-15 $@

$(UTF8:%=$(MACH)/%):	$(MACH)/UTF-8
	$(RM) $@
	$(LN) $(MACH)/UTF-8 $@

mkctype_lex.c:	mkctype_lex.l	mkctype_yacc.tab.h $(HDRS)
	$(LEX) $(LFLAGS) mkctype_lex.l > $@

mkctype_yacc.tab.c mkctype_yacc.tab.h:	mkctype_yacc.y $(HDRS)
	$(YACC) $(YFLAGS) mkctype_yacc.y

clean:
	$(RM) $(OBJS) $(CLEANFILES)
	$(RM) -r $(MACH)

#
# Lint does nothing for us, because yacc and lex outputs are themselves
# not lint clean.  This is something that it would be good to address.
#
lint:

#
# Likewise, the yacc and lex outputs are not cstyle clean.
#
check:
	$(CSTYLE) -cPp $(HDRS)


#
# Rules for building encoding data files.
#
$(MACH)/%: data/%.src $(MACH)/$(PROG)
	$(MACH)/$(PROG) -o $@ $(@:$(MACH)/%=data/%.src)

include ../Makefile.targ
