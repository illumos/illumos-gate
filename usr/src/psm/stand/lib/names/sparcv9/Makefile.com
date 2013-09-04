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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# psm/stand/lib/names/sparcv9/Makefile.com
#
# SPARCv9 architecture Makefile for Standalone Library
# Platform-specific, but shared between platforms.
# Firmware dependent.
#

include $(TOPDIR)/Makefile.master
include $(TOPDIR)/lib/Makefile.lib
include $(TOPDIR)/psm/stand/lib/Makefile.lib

PSMSYSHDRDIR =	$(TOPDIR)/psm/stand
STANDDIR =	$(TOPDIR)/stand

LIBNAMES =	libnames.a
LINTLIBNAMES =	llib-lnames.ln

# ARCHCMNDIR - common code for several machines of a given isa
# OBJSDIR - where the .o's go

ARCHCMNDIR =	../../sparc/common
OBJSDIR =	objs

CMNSRCS =	uname-i.c uname-m.c mfgname.c
NAMESRCS =	$(PLATSRCS) $(CMNSRCS)
NAMEOBJS =	$(NAMESRCS:%.c=%.o)

OBJS =		$(NAMEOBJS:%=$(OBJSDIR)/%)
L_OBJS =	$(OBJS:%.o=%.ln)
L_SRCS =	$(CMNSRCS:%=$(ARCHCMNDIR)/%) $(PLATSRCS)

CPPINCS +=	-I$(SRC)/uts/common
CPPINCS +=	-I$(SRC)/uts/sun
CPPINCS +=	-I$(SRC)/uts/sparc
CPPINCS +=	-I$(SRC)/uts/sparc/$(ARCHVERS)
CPPINCS +=	-I$(SRC)/uts/sun4
CPPINCS +=	-I$(SRC)/uts/$(PLATFORM)
CPPINCS += 	-I$(ROOT)/usr/include/$(ARCHVERS)
CPPINCS += 	-I$(ROOT)/usr/platform/$(PLATFORM)/include
CPPINCS += 	-I$(PSMSYSHDRDIR)
CPPINCS += 	-I$(STANDDIR)
CPPINCS += 	-I$(STANDDIR)/lib/sa
CPPFLAGS =	$(CPPINCS) $(CCYFLAG)$(PSMSYSHDRDIR)
CPPFLAGS +=	-D_KERNEL
ASFLAGS =	-P -D__STDC__ -D_ASM $(CPPINCS)
CFLAGS +=	$(CCVERBOSE)

.KEEP_STATE:

.PARALLEL:	$(OBJS) $(L_OBJS)

all install: $(LIBNAMES) .WAIT

lint: $(LINTLIBNAMES)

clean:
	$(RM) $(OBJS) $(L_OBJS)

clobber: clean
	$(RM) $(LIBNAMES) $(LINTLIBNAMES)

$(LIBNAMES): $(OBJSDIR) .WAIT $(OBJS)
	$(BUILD.AR) $(OBJS)

$(LINTLIBNAMES): $(OBJSDIR) .WAIT $(L_OBJS)
	@$(ECHO) "\nlint library construction:" $@
	@$(LINT.lib) -o names $(L_SRCS)

$(OBJSDIR):
	-@[ -d $@ ] || mkdir $@

#
# build rules using standard library object subdirectory
#
$(OBJSDIR)/%.o: $(ARCHCMNDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.o: $(ARCHCMNDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.ln: $(ARCHCMNDIR)/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))
	@$(MV) $(@F) $@

$(OBJSDIR)/%.ln: $(ARCHCMNDIR)/%.s
	@($(LHEAD) $(LINT.s) $< $(LTAIL))
	@$(MV) $(@F) $@
