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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# psm/stand/boot/i386/Makefile.com

include $(TOPDIR)/psm/stand/boot/Makefile.boot

BOOTSRCDIR	= ../..

TOP_CMN_DIR	= $(SRC)/common
PROM_DIR	= $(SRC)/uts/intel/promif
CMN_DIR		= $(BOOTSRCDIR)/common
MACH_DIR	= ../common
PLAT_DIR	= .
PAMD64_DIR	= $(BOOTSRCDIR)/amd64
BOOT_DIR	= $(SRC)/psm/stand/boot

TOP_CMN_C_SRC	= getoptstr.c string.c ufsops.c hsfs.c
TOP_CMN_C_SRC	+= memcpy.c memmove.c memset.c bcopy.c bzero.c
PROM_C_SRC	= prom_printf.c prom_putchar.c prom_env.c
CMN_C_SRC	= heap_kmem.c readfile.c

PAMD64_C_SRC	= alloc.c context.c cpu.c handoff.c memlist.c print.c
PAMD64_C_SRC	+= ptops.c ptxlate.c segments.c vtrap.c
PAMD64_S_SRC	= i386_subr.s
PAMD64_SL_SRC	= locore.s exception.s

ASSYM_H		= assym.h
GENASSYM	= genassym
GENASSYM_FILES	= $(ASSYM_H) $(GENASSYM)

$(PAMD64_SL_SRC:%.s=%.o)	:= AS = $(amd64_AS)
$(PAMD64_SL_SRC:%.s=%.o)	:= ASFLAGS = -P	$(CPPDEFS) -D_ASM $(CPPINCS)

MACH_C_SRC	= bios.c bootflags.c bootops.c bootprop.c
MACH_C_SRC	+= boot_plat.c boot_ramdisk.c console.c
MACH_C_SRC	+= keyboard.c keyboard_table.c memory.c
MACH_C_SRC	+= multiboot.c standalloc.c vga.c
MACH_C_SRC	+= bootenv.c vgaprobe.c check_iopath.c

BIOS_C_SRC	= biosutil.c

C_SRC		= $(TOP_CMN_C_SRC) $(CMN_C_SRC) $(MACH_C_SRC) $(ARCH_C_SRC)
C_SRC		+= $(PAMD64_C_SRC) $(PROM_C_SRC)
S_SRC		= $(ARCH_S_SRC) $(PAMD64_S_SRC) $(PAMD64_SL_SRC)

START_OBJS	= $(START_S_SRC:%.s=%.o)
OBJS		= $(C_SRC:%.c=%.o) $(S_SRC:%.s=%.o)
L_OBJS		= $(OBJS:%.o=%.ln)

# Note: the BIOS_S_SRC (biosint.s) must come first
BIOS_OBJS	= $(BIOS_S_SRC:%.s=%.o) $(BIOS_C_SRC:%.c=%.o)

ELFCONV =	mkbin
BIOSINT	=	biosint
UNIBOOT =	multiboot

ROOT_PSM_BIOSINT = $(ROOT_PSM_DIR)/$(BIOSINT)
ROOT_PSM_UNIBOOT = $(ROOT_PSM_DIR)/$(UNIBOOT)

.KEEP_STATE:

.PARALLEL:	$(OBJS) $(START_OBJS) $(L_OBJS)

all: $(ELFCONV) $(UNIBOOT) $(BIOSINT)

SYSDIR	=	$(TOPDIR)/uts

CPPDEFS		= $(ARCHOPTS) -D$(PLATFORM) -D_BOOT -D_KERNEL -D_MACHDEP
CPPINCS		+= -I$(TOP_CMN_DIR)
CPPINCS		+= -I. -I$(PAMD64_DIR)
CPPINCS		+= -I$(PSMSYSHDRDIR)
CPPINCS		+= -I$(ROOT)/usr/platform/$(PLATFORM)/include
CPPINCS		+= -I$(TOPDIR)/uts/intel -I$(TOPDIR)/uts/i86pc
CPPINCS		+= -I$(TOPDIR)/uts/common
CPPINCS		+= -I$(STANDDIR)/lib/sa
CPPINCS		+= -I$(STANDDIR)
CPPINCS		+= -I$(BOOT_DIR)/i386/common

CPPFLAGS	= $(CPPDEFS) $(CPPINCS)
CPPFLAGS	+= $(CCYFLAG)$(SYSDIR)/common
ASFLAGS =	-P $(CPPDEFS) -D__STDC__ -D_BOOT -D_ASM $(CPPINCS)

CFLAGS	=	../common/i86.il $(COPTFLAG)

#
# Force 16-bit alignment in multiboot
#
CFLAGS	+=	-xcache=0/16/0:0/16/0
#
# This should be globally enabled!
#
CFLAGS	+=	$(CCVERBOSE)

YFLAGS	=	-d

#
# Loader flags used to build biosint
#
BIOS_LOADMAP	= bios_loadmap
BIOS_MAPFILE	= $(MACH_DIR)/biosint.map
BIOS_LDFLAGS	= -dn -m -M $(BIOS_MAPFILE)

$(ELFCONV): $(MACH_DIR)/$$(@).c
	$(NATIVECC) -O -o $@ $(MACH_DIR)/$@.c

$(BIOSINT): $(ELFCONV) $(BIOS_MAPFILE) $(BIOS_OBJS)
	$(LD) $(BIOS_OBJS) $(BIOS_LDFLAGS) -o $@.elf > $(BIOS_LOADMAP)
	cp $@.elf $@.strip
	$(STRIP) $@.strip
	$(RM) $@; ./$(ELFCONV) $@.strip $@

#
# Loader flags used to build unified boot
#
UNI_LOADMAP	= loadmap
UNI_MAPFILE	= $(MACH_DIR)/mapfile
UNI_LDFLAGS	= -dn -m -M $(UNI_MAPFILE)

#
# Object files used to build unified boot
# Note: START_OBJS must come within first 8K to comply with Multiboot Spec
#
UNI_OBJS	= $(START_OBJS) $(OBJS)
UNI_L_OBJS	= $(UNI_OBJS:%.o=%.ln)

$(UNIBOOT): $(UNI_MAPFILE) $(UNI_OBJS)
	$(LD) $(UNI_LDFLAGS) -o $@ $(UNI_OBJS) > $(UNI_LOADMAP)
	$(POST_PROCESS)

$(UNIBOOT)_lint: $(UNI_L_OBJS)
	$(LINT.c) $(UNI_L_OBJS)

ROOT_BOOT_DIR = $(ROOT)/boot
ROOT_BOOT_SOL_DIR = $(ROOT_BOOT_DIR)/solaris

$(ROOT_BOOT_DIR): $(ROOT)
	-$(INS.dir.root.sys)

$(ROOT_BOOT_SOL_DIR): $(ROOT_BOOT_DIR)
	-$(INS.dir.root.sys)

$(ROOT_BOOT_SOL_DIR)/%: % $(ROOT_BOOT_SOL_DIR)
	$(INS.file)

#
# AMD64 genassym fun
#
$(PAMD64_S_SRC:%.s=%.o)		: $(GENASSYM_FILES)
$(PAMD64_SL_SRC:%.s=%.o)	: $(GENASSYM_FILES)

GENASSYM_SRC	= $(PAMD64_DIR)/$(GENASSYM:%=%.c)
$(GENASSYM)	:= CFLAGS = -D__sun $(ENVCPPFLAGS1) $(ENVCPPFLAGS2) \
		   $(ENVCPPFLAGS3) $(ENVCPPFLAGS4)

$(GENASSYM): $(GENASSYM_SRC)
	$(NATIVECC) $(CFLAGS) -o $@ $(GENASSYM_SRC)

OFFSETS		= $(PAMD64_DIR)/offsets.in 
$(ASSYM_H)	:= CC = $(amd64_CC)
$(ASSYM_H)	:= CFLAGS = -g -xarch=amd64 -xc99=%none \
		   -D__sun $(CPPFLAGS)
$(ASSYM_H)	:= CCYFLAG = -g -YI,

$(ASSYM_H): $(OFFSETS) $(GENASSYM)
	$(GENOFFSETS) -s $(CTFSTABS) -r $(CTFCONVERT) \
	    $(CC) $(CFLAGS) $(GOFLAGS) <$(OFFSETS) >$@
	./$(GENASSYM) >>$@

$(START_OBJS):	$(ASSYM_H)

include $(BOOTSRCDIR)/Makefile.rules

clean:
	$(RM) $(OBJS) $(BIOS_OBJS)
	$(RM) $(L_OBJS) $(GENASSYM_FILES)
	$(RM) $(BIOSINT).elf a.out core

clobber: clean
	$(RM) $(ELFCONV) $(UNIBOOT) $(UNI_LOADMAP) $(BIOSINT) $(BIOS_LOADMAP)
	$(RM) $(UFSBOOT) $(NFSBOOT)

include $(TOPDIR)/Makefile.psm.targ

install: $(ROOT_PSM_UNIBOOT) $(ROOT_PSM_BIOSINT)

lint:	all $(UNIBOOT)_lint

FRC:
