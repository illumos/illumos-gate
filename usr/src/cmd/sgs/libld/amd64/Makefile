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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

BASEPLAT=	amd64

include		$(SRC)/cmd/sgs/libld/Makefile.com

#
# Share machsym.c with the 32-bit i386 directory since
# they both need the Elf32 and the Elf64 code.
#
L_MACHSRCS32=	../i386/machrel.c ../i386/machsym.c
L_MACHSRCS64 =	machrel.c ../i386/machsym.c \
		amd64unwind.c ../../tools/common/leb128.c

CHKSRCS +=	machrel.c ../i386/machrel.c amd64unwind.c \
		../../tools/common/leb128.c

LIB64=		libld.so.3
$(LIB64) :=	SONAME = $(LIB64)

DBGLIB =	-L ../../liblddbg/$(MACH64)
CONVLIB =	-L ../../libconv/$(MACH64)
ELFLIB =	-L ../../libelf/$(MACH64)
DYNFLAGS +=	$(DBGLIB) $(CONVLIB) $(ELFLIB)

SGSMSGTARG +=	$(SGSMSGINTEL)

.PARALLEL:	$(LINTOUT32) $(LINTOUT64)

PICS64=		$(OBJECTS:%=pics64/%) pics64/amd64unwind.o pics64/leb128.o
$(PICS64) :=	amd64_CFLAGS += $(C_PICFLAGS)
CTFMERGE_LIB64= $(CTFMERGE) -t -f -L VERSION -o $@ $(PICS64)
$(PICS64)  :=	CFLAGS += $(CTF_FLAGS)
$(PICS64)  :=	CFLAGS64 += $(CTF_FLAGS)
$(PICS64)  :=	CTFCONVERT_POST = $(CTFCONVERT_O)
$(LIB64)   :=	CTFMERGE_POST = $(CTFMERGE_LIB64)
$(PICS64) :=    CPPFLAGS += -I../../../../uts/intel/amd64/krtld
$(PICS64) :=	CPPFLAGS += -DELF_TARGET_AMD64
$(PICS) :=      CPPFLAGS += -I../../../../uts/intel/ia32/krtld
$(PICS) :=	CPPFLAGS += -DELF_TARGET_386

.PARALLEL:	$(PICS64)

ROOTFS_LIBDIR=		$(VAR_LIBLD_64_ROOTFS_LIBDIR)
ROOTFS_DYNLIB64=	$(ROOTFS_LIBDIR)/$(LIB64)
$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

$(LINTOUT32) :=	CPPFLAGS += -I../../../../uts/intel/ia32/krtld \
		-DELF_TARGET_386
$(LINTOUT64) :=	CPPFLAGS += -I../../../../uts/intel/amd64/krtld \
		-DELF_TARGET_AMD64
.KEEP_STATE:

all:		$(DYNLIB) $(LIBLINKS) $(LIB64)


LINK.LIB64 = $(CC) $(amd64_CFLAGS) -o $@ -G $(DYNFLAGS) $(PICS64) $(LDLIBS)
$(LIB64) $(SGSPROTO)/$(LIB64): pics64 .WAIT $$(PICS64) $(MAPFILES)
	$(LINK.LIB64)
	$(POST_PROCESS_SO)

lint:		$(LINTLIB64) $(LINTOUT64)

native:		$(SGSPROTO)/$(DYNLIB) $(SGSPROTO)/$(LIB64)

native-proto:
		-@mkdir -p proto/$(MACH) proto/$(MACH64)

pics64:
		-@mkdir -p $@


install package:	all $(ROOTFS_DYNLIB) $(ROOTFS_DYNLIB64)


clean: clean64

clean64:
	-$(RM) $(PICS64)

clobber: clobber64
clobber64:
	-$(RM) $(LIB64)

delete:
		$(RM) $(DYNLIB) $(LIB64)

#
# Grab 32bit i386 files for libld.so.2
#
pics/machrel.o:	../i386/machrel.c
		$(COMPILE.c) -o $@ -D_ELF32 ../i386/machrel.c
		$(POST_PROCESS_O)

pics/machsym.o:	../i386/machsym.c
		$(COMPILE.c) -o $@ -D_ELF32 ../i386/machsym.c
		$(POST_PROCESS_O)

pics64/machsym.o:	../i386/machsym.c
		$(COMPILE.c) -o $@ -D_ELF64 ../i386/machsym.c
		$(POST_PROCESS_O)


include		$(SRC)/cmd/sgs/libld/Makefile.targ
include		../../Makefile.sub.64

$(LIBLINKS) :=	DYNLIB=$(LIB64)

pics64/%.o:	$(SRCBASE)/uts/intel/amd64/krtld/%.c
		$(COMPILE.c) -o $@ -D_ELF64 $<
		$(POST_PROCESS_O)

pics/%.o:	$(SRCBASE)/uts/intel/ia32/krtld/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)
