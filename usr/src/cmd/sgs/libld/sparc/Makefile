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
# ident	"%Z%%M%	%I%	%E% SMI"
#

BASEPLAT=	sparc
include		$(SRC)/cmd/sgs/libld/Makefile.com

L_MACHSRCS32=	machrel.c machsym.c
L_MACHSRCS64=	$(L_MACHSRCS32)
CHKSRCS=	$(SRCBASE)/uts/common/krtld/reloc.h $(L_MACHSRCS32)

LIB64=		libld.so.3
$(LIB64) :=	SONAME = $(LIB64)

PICS64=		$(OBJECTS:%=pics64/%)
$(PICS64)  :=	sparc_CFLAGS += -xregs=no%appl -K pic
$(PICS64)  :=	CFLAGS += $(CTF_FLAGS)
$(PICS64)  :=	CFLAGS64 += $(CTF_FLAGS)
$(PICS64)  :=	CTFCONVERT_POST = $(CTFCONVERT_O)
CTFMERGE_LIB64= $(CTFMERGE) -t -f -L VERSION -o $@ $(PICS64)
$(LIB64)   :=	CTFMERGE_POST = $(CTFMERGE_LIB64)
CPPFLAGS +=	-I../../../../uts/sparc/krtld

SGSMSGTARG +=	$(SGSMSGSPARC)

.PARALLEL:	$(PICS64)

ROOTFS_DYNLIB64=	$(ROOTFS_LIBDIR)/$(LIB64)
$(ROOTFS_DYNLIB64) :=	FILEMODE= 755

.KEEP_STATE:

all:		$(DYNLIB) $(LIBLINKS) .WAIT $(LIB64)


$(LIB64) $(SGSPROTO)/$(LIB64): \
		pics64 .WAIT $$(PICS64) $(MAPFILES)
		$(CC) -o $@ -G $(DYNFLAGS) $(PICS64) $(LDLIBS)
		$(POST_PROCESS_SO)

native:		$(SGSPROTO)/$(DYNLIB) $(SGSPROTO)/$(LIB64)

native-proto:
		-@mkdir -p proto/$(MACH) proto/$(MACH64)

lint:		$(LINTLIB64) $(LINTOUT64)
.PARALLEL:	$(LINTOUT32) $(LINTOUT64)

pics64:
		-@mkdir -p $@

install \
package:	all $(ROOTFS_DYNLIB) $(ROOTFS_DYNLIB64)


clean: clean64

clean64:
		-$(RM) $(PICS64)

clobber:	clobber64

clobber64:
		-$(RM) $(LIB64)

delete:
		$(RM) $(DYNLIB) $(LIB64)


include		$(SRC)/cmd/sgs/libld/Makefile.targ

pics64/%.o:	$(SRCBASE)/uts/sparc/krtld/%.c
		$(COMPILE.c) -o $@ -D_ELF64 $<
		$(POST_PROCESS_O)

pics/%.o:	$(SRCBASE)/uts/sparc/krtld/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)
