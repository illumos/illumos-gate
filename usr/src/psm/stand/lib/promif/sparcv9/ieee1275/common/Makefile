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
# psm/stand/lib/promif/sparcv9/ieee1275/common/Makefile
#

# usr/src
TOPDIR =	../../../../../../..

include $(TOPDIR)/Makefile.master
include $(TOPDIR)/lib/Makefile.lib
include $(TOPDIR)/psm/stand/lib/Makefile.lib
include $(TOPDIR)/psm/Makefile.psm.64

CFLAGS64	+= -xchip=ultra $(CCABS32)
CERRWARN	+= -_gcc=-Wno-parentheses

PROMDIR =	$(TOPDIR)/psm/promif/ieee1275/common
SYSDIR =	$(TOPDIR)/uts

LIBPROM =	libprom.a
LINTLIBPROM =	llib-lprom.ln

PROM_CFILES =			\
	prom_2path.c		\
	prom_boot.c		\
	prom_devname.c		\
	prom_devtype.c		\
	prom_enter.c		\
	prom_env.c		\
	prom_exit.c		\
	prom_fb.c		\
	prom_getchar.c		\
	prom_gettime.c		\
	prom_handler.c		\
	prom_inpath.c		\
	prom_interp.c		\
	prom_io.c		\
	prom_kbd.c		\
	prom_key.c		\
	prom_node.c		\
	prom_outpath.c		\
	prom_panic.c		\
	prom_path.c		\
	prom_phandle.c		\
	prom_printf.c		\
	prom_prop.c		\
	prom_putchar.c		\
	prom_reboot.c		\
	prom_stdin.c		\
	prom_stdout.c		\
	prom_string.c		\
	prom_test.c		\
	prom_trap.c		\
	prom_version.c		\
	prom_wrtestr.c

PROM_SFILES =

PROM_FILES = 	$(PROM_CFILES) $(PROM_SFILES)

KARCH =		sun4u
MMU =		sfmmu

OBJSDIR =	objs

PROM_COBJ =	$(PROM_CFILES:%.c=$(OBJSDIR)/%.o)
PROM_SOBJ =	$(PROM_SFILES:%.s=$(OBJSDIR)/%.o)
OBJS =		$(PROM_COBJ) $(PROM_SOBJ)
L_OBJS =	$(OBJS:%.o=%.ln)
L_SRCS =	$(PROM_FILES:%=$(PROMDIR)/%)

ARCHOPTS =	-DSTACK_64BIT -Dsun4u
ASFLAGS =	-P -D__STDC__ -D_BOOT -D_ASM
CPPDEFS	=	$(ARCHOPTS) -D$(KARCH) -D_BOOT -D_KERNEL -D_MACHDEP
CPPINCS =	-I. -I$(SYSDIR)/sun4 -I$(SYSDIR)/$(KARCH) -I$(SYSDIR)/$(MMU) \
		-I$(SYSDIR)/sparc/v9 -I$(SYSDIR)/sparc \
		-I$(SYSDIR)/sun -I$(SYSDIR)/common
CPPFLAGS =	$(CPPDEFS) $(CPPINCS) $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)

.KEEP_STATE:

.PARALLEL:	$(OBJS) $(L_OBJS)

all install: $(LIBPROM)

lint: $(LINTLIBPROM)

clean:
	$(RM) $(OBJS) $(L_OBJS)

clobber: clean
	$(RM) $(LIBPROM) $(LINTLIBPROM)

$(LIBPROM): $(OBJSDIR) .WAIT $(OBJS)
	$(BUILD.AR) $(OBJS)

$(LINTLIBPROM): $(OBJSDIR) .WAIT $(L_OBJS)
	@$(ECHO) "\nlint library construction:" $@
	@$(LINT.lib) -o prom $(L_SRCS)

$(OBJSDIR):
	-@[ -d $@ ] || mkdir $@

#
# build rules using standard library object subdirectory
#
$(OBJSDIR)/%.o: $(PROMDIR)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.o: $(PROMDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

$(OBJSDIR)/%.ln: $(PROMDIR)/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))
	@$(MV) $(@F) $@

$(OBJSDIR)/%.ln: $(PROMDIR)/%.s
	@($(LHEAD) $(LINT.s) $< $(LTAIL))
	@$(MV) $(@F) $@
