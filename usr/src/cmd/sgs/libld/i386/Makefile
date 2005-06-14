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

BASEPLAT=	i386

include		$(SRC)/cmd/sgs/libld/Makefile.com
COPTFLAG=

LIB64=		libld.so.3
$(LIB64) :=	SONAME = $(LIB64)

L_MACHSRCS32=	machrel.c machsym.c
L_MACHSRCS64=	../amd64/machrel.c machsym.c ../amd64/amd64unwind.c \
		../../tools/common/leb128.c

CHKSRCS =  machrel.c ../amd64/machrel.c ../amd64/amd64unwind.c \
	    ../../tools/common/leb128.c

PICS64=		$(OBJECTS:%=pics64/%) pics64/amd64unwind.o pics64/leb128.o
$(PICS64) :=	i386_CFLAGS += $(C_PICFLAGS)
CTFMERGE_LIB64= $(CTFMERGE) -t -f -L VERSION -o $@ $(PICS64)
$(PICS64)  :=	CFLAGS += $(CTF_FLAGS)
$(PICS64)  :=	CFLAGS64 += $(CTF_FLAGS)
$(PICS64)  :=	CTFCONVERT_POST = $(CTFCONVERT_O)
$(LIB64)   :=	CTFMERGE_POST = $(CTFMERGE_LIB64)
$(PICS64) :=	CPPFLAGS +=	-I../../../../uts/intel/amd64/krtld
$(PICS64) :=	CPPFLAGS += -DELF_TARGET_AMD64

SGSMSGTARG +=	$(SGSMSGINTEL)

.PARALLEL:	$(PICS64)

ROOTFS_DYNLIB64=	$(ROOTFS_LIBDIR)/$(LIB64)
$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

$(PICS) :=	CPPFLAGS += -I../../../../uts/$(PLAT)/krtld
$(LINTOUT32) :=	CPPFLAGS += -I../../../../uts/$(PLAT)/krtld
$(LINTOUT64) :=	CPPFLAGS += -I../../../../uts/$(PLAT)/krtld \
		-DELF_TARGET_AMD64

.KEEP_STATE:

all:		$(DYNLIB) $(LIBLINKS) $(LIB64)

$(LIB64) $(SGSPROTO)/$(LIB64): \
		pics64 .WAIT $$(PICS64) $(MAPFILES)
		$(CC) -o $@ $(GSHARED) $(DYNFLAGS) $(PICS64) $(LDLIBS)
		$(POST_PROCESS_SO)

native:		$(SGSPROTO)/$(DYNLIB) $(SGSPROTO)/$(LIB64)

native-proto:
		-@mkdir -p proto/$(MACH) proto/$(MACH64)


lint:		$(LINTLIB64) $(LINTOUT64)
.PARALLEL:	$(LINTOUT32) $(LINTOUT64)

pics64:
		-@mkdir -p $@

clean: clean64

clean64:
		-$(RM) $(PICS64)

clobber:	clobber64

clobber64:
		-$(RM) $(LIB64)

delete:
		$(RM) $(DYNLIB) $(LIB64)

install \
package:	all $(ROOTFS_DYNLIB) $(ROOTFS_DYNLIB64)

#
# Grab 64bit amd64 files for libld.so.3
#
pics64/amd64unwind.o: ../amd64/amd64unwind.c
		$(COMPILE.c) -o $@ -D_ELF64 ../amd64/amd64unwind.c
		$(POST_PROCESS_O)

pics64/machrel.o: ../amd64/machrel.c
		$(COMPILE.c) -o $@ -D_ELF64 ../amd64/machrel.c
		$(POST_PROCESS_O)

include		$(SRC)/cmd/sgs/libld/Makefile.targ

pics64/%.o:	$(SRCBASE)/uts/intel/amd64/krtld/%.c
		$(COMPILE.c) -o $@ -D_ELF64 $<
		$(POST_PROCESS_O)

pics/%.o:	$(SRCBASE)/uts/$(PLAT)/krtld/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)
