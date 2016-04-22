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
# Copyright 2016 Joyent, Inc.
#

LIBRARY	=	lx_vdso.a
VERS =		.1

include $(SRC)/lib/commpage/Makefile.shared.com

COBJS =		vdso_main.o vdso_subr.o
OBJECTS =	$(COBJS) $(COMMPAGE_OBJS)

include ../../../../Makefile.lib
include ../../Makefile.lx

#
# Since our name doesn't start with "lib", Makefile.lib incorrectly
# calculates LIBNAME. Therefore, we set it here.
#
LIBNAME =	lx_vdso

MAPFILES =	../common/mapfile-vers
MAPOPTS =	$(MAPFILES:%=-M%)

ASOBJS  =	vdso_subr.o
COBJS  =	vdso_main.o
OBJECTS =	$(ASOBJS) $(COBJS) $(COMMPAGE_OBJS)

SRCDIR =	../common

ASSRCS =	$(ASOBJS:%.o=$(ISASRCDIR)/%.s)
CSRCS =		$(COBJS:%.o=$(SRCDIR)/%.c)
SRCS =		$(ASSRCS) $(CSRCS)

LIBS =		$(DYNLIB)
DYNFLAGS +=	$(DYNFLAGS_$(CLASS))
DYNFLAGS +=	$(MAPOPTS)
LDLIBS +=
ASFLAGS =	-P $(ASFLAGS_$(CURTYPE)) -D_ASM


LIBS =		$(DYNLIB)

CLEANFILES =	$(DYNLIB)
ROOTLIBDIR =	$(ROOT)/usr/lib/brand/lx
ROOTLIBDIR64 =	$(ROOT)/usr/lib/brand/lx/$(MACH64)

VDSO_TOOL =	../tools/vdso_tool

.KEEP_STATE:

#
# While $(VDSO_TOOL) performs most of the transformations required to
# construct a correct VDSO object, we still make use of $(ELFEDIT).  To
# remove the $(ELFEDIT) requirement would mean shouldering the burden of
# becoming a link-editor; this dark lore is best left to the linker aliens.
#
all: $(LIBS)
	$(ELFEDIT) -e "dyn:value -add VERSYM $$($(ELFEDIT) \
	    -e 'shdr:dump .SUNW_versym' $(DYNLIB) | \
	    $(AWK) '{ if ($$1 == "sh_addr:") { print $$2 } }')" $(DYNLIB)
	$(VDSO_TOOL) -f $(DYNLIB)

lint: $(LINTLIB) lintcheck

include ../../../../Makefile.targ
include $(SRC)/lib/commpage/Makefile.shared.targ

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

pics/vdso_main.o := CPPFLAGS += $(COMMPAGE_CPPFLAGS)
pics/vdso_subr.o := ASFLAGS += -I$(SRC)/uts/common/brand/lx
