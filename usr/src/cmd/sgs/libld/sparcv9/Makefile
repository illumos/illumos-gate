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

BASEPLAT=	sparc
include		$(SRC)/cmd/sgs/libld/Makefile.com

#
# Share machrel.c with the 32-bit sparc directory since
# they both need the Elf32 and the Elf64 code.
#
L_MACHSRCS32=	../$(MACH)/machrel.c ../$(MACH)/machsym.c
L_MACHSRCS64=	$(L_MACHSRCS32)
CHKSRCS=	$(SRCBASE)/uts/common/krtld/reloc.h $(L_MACHSRCS32)

LIB64=		libld.so.3
$(LIB64) :=	SONAME = $(LIB64)

DBGLIB =	-L ../../liblddbg/$(MACH64)
ELFLIB =	-L ../../libelf/$(MACH64)

CONVLIBDIR=	$(CONVLIBDIR64)
LDDBGLIBDIR=	$(LDDBGLIBDIR64)
ELFLIBDIR=	$(ELFLIBDIR64)

LINTFLAGS64 +=	$(VAR_LINTFLAGS64)

SGSMSGTARG +=	$(SGSMSGSPARC)

.PARALLEL:	$(LINTOUT32) $(LINTOUT64)

PICS64=		$(OBJECTS:%=pics64/%)
$(PICS64) :=	sparcv9_CFLAGS += -xregs=no%appl -K pic
CPPFLAGS +=     -I../../../../uts/sparc/krtld
CTFMERGE_LIB64= $(CTFMERGE) -t -f -L VERSION -o $@ $(PICS64)
$(PICS64)  :=	CFLAGS += $(CTF_FLAGS)
$(PICS64)  :=	CFLAGS64 += $(CTF_FLAGS)
$(PICS64)  :=	CTFCONVERT_POST = $(CTFCONVERT_O)
$(LIB64)   :=	CTFMERGE_POST = $(CTFMERGE_LIB64)

.PARALLEL:	$(PICS64)

ROOTFS_LIBDIR=		$(VAR_LIBLD_64_ROOTFS_LIBDIR)
ROOTFS_DYNLIB64=	$(ROOTFS_LIBDIR)/$(LIB64)
$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

.KEEP_STATE:

all:		$(DYNLIB) $(LIBLINKS) .WAIT $(LIB64)

$(LIB64) $(SGSPROTO)/$(LIB64): \
		pics64 .WAIT $$(PICS64) $(MAPFILES)
		$(CC) $(sparcv9_XARCH) -o $@ -G $(DYNFLAGS) $(PICS64) $(LDLIBS)
		$(POST_PROCESS_SO)

lint:		$(LINTLIB64) $(LINTOUT64)

#
# Share machrel.c with the base architecture, since they
# both need all the Elf32 and Elf64 code.
#
pics/machrel.o:	../sparc/machrel.c
		$(COMPILE.c) -o $@ ../sparc/machrel.c
		$(POST_PROCESS_O)

pics64/machrel.o:	../sparc/machrel.c
		$(COMPILE.c) -D_ELF64 -o $@ ../sparc/machrel.c
		$(POST_PROCESS_O)

pics/machsym.o:	../sparc/machsym.c
		$(COMPILE.c) -o $@ ../sparc/machsym.c
		$(POST_PROCESS_O)

pics64/machsym.o:	../sparc/machsym.c
		$(COMPILE.c) -D_ELF64 -o $@ ../sparc/machsym.c
		$(POST_PROCESS_O)

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

include		$(SRC)/cmd/sgs/libld/Makefile.targ
include		../../Makefile.sub.64

$(LIBLINKS) :=	DYNLIB=$(LIB64)

pics64/%.o:	$(SRCBASE)/uts/sparc/krtld/%.c
		$(COMPILE.c) -o $@ -D_ELF64 $<
		$(POST_PROCESS_O)

pics/%.o:	$(SRCBASE)/uts/sparc/krtld/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)
