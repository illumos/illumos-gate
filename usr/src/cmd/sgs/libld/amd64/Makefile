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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

E_TOOLOBJS =	leb128.o
L_MACHOBJS32 =	machrel.intel32.o	machsym.intel32.o
L_MACHOBJS64 =	machrel.amd64.o		machsym.intel64.o	unwind.amd64.o

include		../Makefile.com

.KEEP_STATE:

ROOTFS_LIBDIR64 = \
		$(VAR_LIBLD_64_ROOTFS_LIBDIR)

ROOTFS_DYNLIB64 = \
		$(DYNLIB:%=$(ROOTFS_LIBDIR64)/%)

SGSMSGCHK =	../common/libld.chk.msg
SGSMSGTARG +=	$(SGSMSGINTEL)

#
# For cross-compilation, it is necessary to trigger the correct include files
# (see sys/elf.h).
#
ELFTARGET64 =	-DELF_TARGET_AMD64
ELFTARGET32 =	-DELF_TARGET_386

ELFLIBDIR =	$(ELFLIBDIR64)
LDDBGLIBDIR =	$(LDDBGLIBDIR64)
CONVLIBDIR =	$(CONVLIBDIR64)

$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

all:		$(DYNLIB) $(LIBLINKS)

install \
package:	all $(ROOTFS_DYNLIB64)

include		../Makefile.targ
include		../../Makefile.sub.64

# Associate ELF32 and ELF64 objects to the appropriate headers.

pics/%32.o :=	CPPFLAGS += -I$(SRCBASE)/uts/$(VAR_PLAT_i386)/krtld
pics/%64.o :=	CPPFLAGS += -I$(SRCBASE)/uts/$(VAR_PLAT_amd64)/krtld

# Associate the various lint targets with the appropriate headers/files.

$(LINTOUT32) :=	CPPFLAGS += -I$(SRCBASE)/uts/$(VAR_PLAT_i386)/krtld \
		    $(ELFTARGET32)
$(LINTOUT64) :=	CPPFLAGS += -I$(SRCBASE)/uts/$(VAR_PLAT_amd64)/krtld \
		    $(ELFTARGET64) -D_ELF64
$(LINTLIB32) :=	CPPFLAGS += -I$(SRCBASE)/uts/$(VAR_PLAT_i386)/krtld \
		    $(ELFTARGET32)
$(LINTLIB64) :=	CPPFLAGS += -I$(SRCBASE)/uts/$(VAR_PLAT_amd64)/krtld \
		    $(ELFTARGET64) -D_ELF64

LINTSRCS32 +=	$(G_MACHOBJS32:%32.o=$(SRCBASE)/uts/$(VAR_PLAT_i386)/krtld/%.c)
LINTSRCS64 +=	$(G_MACHOBJS64:%64.o=$(SRCBASE)/uts/$(VAR_PLAT_amd64)/krtld/%.c)

# Compensate chkmsg with the doreloc family.

CHKSRCS +=	$(G_MACHOBJS32:%32.o=$(SRCBASE)/uts/$(VAR_PLAT_i386)/krtld/%.c)
CHKSRCS +=	$(G_MACHOBJS64:%64.o=$(SRCBASE)/uts/$(VAR_PLAT_amd64)/krtld/%.c)

pics/%32.o: \
		$(SRCBASE)/uts/$(VAR_PLAT_i386)/krtld/%.c
		$(COMPILE.c) -o $@ $(ELFTARGET32) $<
		$(POST_PROCESS_O)

pics/%64.o: \
		$(SRCBASE)/uts/$(VAR_PLAT_amd64)/krtld/%.c
		$(COMPILE.c) -o $@ $(ELFTARGET64) -D_ELF64 $<
		$(POST_PROCESS_O)
