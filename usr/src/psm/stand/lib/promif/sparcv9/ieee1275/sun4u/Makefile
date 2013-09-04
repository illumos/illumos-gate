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
# psm/stand/boot/sparcv9/ieee1275/sun4u/Makefile
#
#
TOPDIR =	../../../../../../..

include $(TOPDIR)/Makefile.master
include $(TOPDIR)/lib/Makefile.lib
include $(TOPDIR)/psm/stand/lib/Makefile.lib
include $(TOPDIR)/psm/Makefile.psm.64

CFLAGS64	+= -xchip=ultra $(CCABS32)

PLATDIR =	$(TOPDIR)/psm/promif/ieee1275/sun4u
PLATSUN4DIR =	$(TOPDIR)/psm/promif/ieee1275/sun4
SYSDIR =	$(TOPDIR)/uts

LIBPLAT =	libplat.a
LINTLIBPLAT =	llib-lplat.ln

PLAT_PFILES = 			\
	prom_serengeti.c	\
	prom_sunfire.c		\
	prom_tlb.c

PLAT_PSUN4FILES =		\
	prom_alloc.c		\
	prom_cpuctl.c		\
	prom_fio.c		\
	prom_getunum.c		\
	prom_heartbeat.c	\
	prom_idprom.c		\
	prom_init.c		\
	prom_macaddr.c		\
	prom_map.c		\
	prom_mem.c		\
	prom_mmu.c		\
	prom_retain.c		\
	prom_sparc.c		\
	prom_vercheck.c		\
	prom_vername.c

KARCH =		sun4u
MMU =		sfmmu

OBJSDIR =	objs

PLAT_POBJ =	$(PLAT_PFILES:%.c=$(OBJSDIR)/%.o)
PLAT_PSUN4OBJ =	$(PLAT_PSUN4FILES:%.c=$(OBJSDIR)/%.o)
OBJS =		$(PLAT_POBJ) $(PLAT_PSUN4OBJ)
L_OBJS =	$(OBJS:%.o=%.ln)
L_SRCS = 	$(PLAT_PFILES:%=$(PLATDIR)/%)
L_SRCS += 	$(PLAT_PSUN4FILES:%=$(PLATSUN4DIR)/%)

ARCHOPTS=	-Dsun4u
ASFLAGS =	-P -D__STDC__ -D_BOOT -D_ASM
CPPDEFS	=	$(ARCHOPTS) -D$(KARCH) -D_BOOT -D_KERNEL -D_MACHDEP
CPPINCS =	-I. -I$(SYSDIR)/sun4 -I$(SYSDIR)/$(KARCH) -I$(SYSDIR)/$(MMU) \
		-I$(SYSDIR)/sparc/v9 -I$(SYSDIR)/sparc \
		-I$(SYSDIR)/sun -I$(SYSDIR)/common
CPPFLAGS=	$(CPPDEFS) $(CPPINCS) $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)

.KEEP_STATE:

.PARALLEL:	$(OBJS) $(L_OBJS)

all install: $(LIBPLAT)

lint: $(LINTLIBPLAT)

clean:
	$(RM) $(OBJS) $(L_OBJS)

clobber: clean
	$(RM) $(LIBPLAT) $(LINTLIBPLAT)

$(LIBPLAT): $(OBJSDIR) .WAIT $(OBJS)
	$(BUILD.AR) $(OBJS)

$(LINTLIBPLAT): $(OBJSDIR) .WAIT $(L_OBJS)
	@$(ECHO) "\nlint library construction:" $@
	@$(LINT.lib) -o plat $(L_SRCS)

$(OBJSDIR):
	-@[ -d $@ ] || mkdir $@

#
# build rules using standard library object subdirectory
#
$(OBJSDIR)/%.o: $(PLATDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.o: $(PLATDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.o: $(PLATSUN4DIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.o: $(PLATSUN4DIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.ln: $(PLATDIR)/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))
	@$(MV) $(@F) $@

$(OBJSDIR)/%.ln: $(PLATDIR)/%.s
	@($(LHEAD) $(LINT.s) $< $(LTAIL))
	@$(MV) $(@F) $@

$(OBJSDIR)/%.ln: $(PLATSUN4DIR)/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))
	@$(MV) $(@F) $@

$(OBJSDIR)/%.ln: $(PLATSUN4DIR)/%.s
	@($(LHEAD) $(LINT.s) $< $(LTAIL))
	@$(MV) $(@F) $@
