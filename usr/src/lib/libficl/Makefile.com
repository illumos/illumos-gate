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

LIBRARY=libficl-sys.a
MAJOR = 4
MINOR = 1.0
VERS=.$(MAJOR).$(MINOR)

OBJECTS= dictionary.o system.o fileaccess.o float.o double.o prefix.o search.o \
	softcore.o stack.o tools.o vm.o primitives.o unix.o utility.o \
	hash.o callback.o word.o loader.o pager.o extras.o \
	loader_emu.o lz4.o

include $(SRC)/lib/Makefile.lib

LIBS=	$(DYNLIB) $(LINTLIB)

FICLDIR=	$(SRC)/common/ficl
C99MODE=	$(C99_ENABLE)
CPPFLAGS +=	-I.. -I$(FICLDIR) -D_LARGEFILE64_SOURCE=1

# As variable "count" is marked volatile, gcc 4.4.4 will complain about
# function argument. So we switch this warning off
# for time being, till gcc 4.4.4 will be replaced.
pics/vm.o := CERRWARN += -_gcc=-Wno-clobbered

LDLIBS +=	-luuid -lc -lm -lumem

HEADERS= $(FICLDIR)/ficl.h $(FICLDIR)/ficltokens.h ../ficllocal.h \
	$(FICLDIR)/ficlplatform/unix.h

pics/%.o:	../softcore/%.c $(HEADERS)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(FICLDIR)/%.c $(HEADERS)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(FICLDIR)/ficlplatform/%.c $(HEADERS)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(FICLDIR)/emu/%.c $(HEADERS)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o:	$(FICLDIR)/softcore/%.c $(HEADERS)
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(LINTLIB) := SRCS=	../$(LINTSRC)

all: $(LIBS)

include $(SRC)/lib/Makefile.targ
