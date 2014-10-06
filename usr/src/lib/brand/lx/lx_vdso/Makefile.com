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
# Copyright 2014 Joyent, Inc.  All rights reserved.
#

LIBRARY	=	lx_vdso.a
VERS =		.1

COBJS =		lx_vdso.o
OBJECTS =	$(COBJS)

include ../../../../Makefile.lib
include ../../Makefile.lx

#
# Since our name doesn't start with "lib", Makefile.lib incorrectly
# calculates LIBNAME. Therefore, we set it here.
#
LIBNAME =	lx_vdso

MAPFILES =	../common/mapfile-vers
MAPOPTS =	$(MAPFILES:%=-M%)

ASOBJS  =	lx_vdso.o
OBJECTS =	$(ASOBJS)

ASSRCS =	$(ASOBJS:%o=$(ISASRCDIR)/%s)
SRCS =		$(ASSRCS)

SRCDIR =	../common
UTSBASE	=	../../../../../uts

LIBS =		$(DYNLIB)
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(MAPOPTS)
LDLIBS +=
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM


LIBS =		$(DYNLIB)

CLEANFILES =	$(DYNLIB)
ROOTLIBDIR =	$(ROOT)/usr/lib/brand/lx
ROOTLIBDIR64 =	$(ROOT)/usr/lib/brand/lx/$(MACH64)

.KEEP_STATE:

all: $(LIBS)
	$(ELFEDIT) -e "dyn:value -add VERSYM $$(elfedit \
	    -e 'shdr:dump .SUNW_versym' $(DYNLIB) | \
	    $(AWK) '{ if ($$1 == "sh_addr:") { print $$2 } }')" $(DYNLIB)
	$(ELFEDIT) -e 'ehdr:ei_osabi ELFOSABI_NONE' $(DYNLIB)
	$(ELFEDIT) -e 'ehdr:ei_abiversion 0' $(DYNLIB)

lint: $(LINTLIB) lintcheck

include ../../../../Makefile.targ

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)
