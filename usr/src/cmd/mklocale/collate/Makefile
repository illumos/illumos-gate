#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL)".  You may
# only use this file in accordance with the terms of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#

PROG= mkcollate
CATEGORY=LC_COLLATE

include ../Makefile.common

CPPFLAGS += -I$(SRC)/lib/libc/port/locale -D_FILE_OFFSET_BITS=64
YFLAGS	= -d -b mkcollate_yacc
LFLAGS	= -t

OBJS = $(MACH)/mkcollate_lex.o $(MACH)/mkcollate_yacc.tab.o
HDRS = common.h
CLEANFILES =	mkcollate_yacc.tab.c mkcollate_yacc.tab.h mkcollate_lex.c

en_COMMON = en_AU en_CA en_GB en_NZ en_US
en_ASCII = $(en_COMMON:%=%.US-ASCII)
en_LATIN1 = $(en_COMMON:%=%.ISO8859-1)
en_LATIN15 = $(en_COMMON:%=%.ISO8859-15)
en_UTF8 = $(en_COMMON:%=%.UTF-8) en_IE.UTF-8
en_LOCALES = $(en_ASCII) $(en_LATIN1) $(en_LATIN15) $(en_UTF8)

.KEEP_STATE:

all: $(MACH)/$(PROG) $(MACHLOCALES)

$(MACH)/$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(en_LATIN1:%=$(MACH)/%): 	$(MACH)/en.ISO8859-1
	$(RM) $@
	$(LN) $(MACH)/en.ISO8859-1 $@

$(en_LATIN15:%=$(MACH)/%): 	$(MACH)/en.ISO8859-15
	$(RM) $@
	$(LN) $(MACH)/en.ISO8859-15 $@

$(en_ASCII:%=$(MACH)/%):	$(MACH)/en.US-ASCII
	$(RM) $@
	$(LN) $(MACH)/en.US-ASCII $@

$(en_UTF8:%=$(MACH)/%):		$(MACH)/en.UTF-8
	$(RM) $@
	$(LN) $(MACH)/en.UTF-8 $@

mkcollate_lex.c:	mkcollate_lex.l	mkcollate_yacc.tab.h $(HDRS)
	$(FLEX) $(LFLAGS) mkcollate_lex.l > $@

mkcollate_yacc.tab.c mkcollate_yacc.tab.h:	mkcollate_yacc.y $(HDRS)
	$(YACC) $(YFLAGS) mkcollate_yacc.y

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
	$(MACH)/$(PROG) -o $@ -I data $(@:$(MACH)/%=data/%.src)

include ../Makefile.targ
