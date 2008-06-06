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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# $LIBRARY is set in lower makefiles so we can have platform and
# processor optimised versions of this library via libmd_psr and libmd_hwcapN

#LIBRARY= libmd.a
VERS= .1

OBJECTS= md4.o md5.o $(MD5_PSR_OBJECTS) sha1.o $(SHA1_PSR_OBJECTS) \
		sha2.o $(SHA2_PSR_OBJECTS)

# Use $(SRC) to include makefiles rather than ../../ because the
# platform subdirs are one level deeper so it would be ../../../ for them
include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.rootfs

LIBS =		$(DYNLIB) $(LINTLIB)
SRCS = \
	$(COMDIR)/md4/md4.c \
	$(COMDIR)/md5/md5.c \
	$(COMDIR)/sha1/sha1.c \
	$(COMDIR)/sha2/sha2.c

COMDIR= $(SRC)/common/crypto

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)
LDLIBS +=	-lc

SRCDIR =	../common
COMDIR =	$(SRC)/common/crypto

CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(C_BIGPICFLAGS)
CPPFLAGS += -I$(SRCDIR)

# The md5 and sha1 code is very careful about data alignment
# but lint doesn't know that, so just shut lint up.
LINTFLAGS += -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTFLAGS64 += -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED


ROOTLINT= $(LINTSRC:%=$(ROOTLIBDIR)/%)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

pics/%.o: $(COMDIR)/md4/%.c
	$(COMPILE.c) -I$(COMDIR)/md4 -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(COMDIR)/md5/%.c
	$(COMPILE.c) -I$(COMDIR)/md5 $(INLINES) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(COMDIR)/sha1/%.c
	$(COMPILE.c) -I$(COMDIR)/sha1 -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(COMDIR)/sha1/sparc/$(PLATFORM)/sha1_asm.s
	$(COMPILE.s) -P -DPIC -D_ASM -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(COMDIR)/sha2/%.c
	$(COMPILE.c) -I$(COMDIR)/sha2 -o $@ $<
	$(POST_PROCESS_O)

#
# Used when building links in /platform/$(PLATFORM)/lib for libmd_psr.so.1
#

LIBMD_PSR_DIRS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib)
LIBMD_PSR_LINKS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MODULE))

LIBMD_PSR64_DIRS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64))
LIBMD_PSR64_LINKS = $(LINKED_PLATFORMS:%=$(ROOT_PLAT_DIR)/%/lib/$(MACH64)/$(MODULE))

INS.slink6 = $(RM) -r $@; $(SYMLINK) ../../$(PLATFORM)/lib/$(MODULE) $@ $(CHOWNLINK) $(CHGRPLINK)

INS.slink64 = $(RM) -r $@; $(SYMLINK) ../../../$(PLATFORM)/lib/$(MACH64)/$(MODULE) $@ $(CHOWNLINK) $(CHGRPLINK)

$(LIBMD_PSR_DIRS):
	-$(INS.dir.root.bin)

$(LIBMD_PSR_LINKS): $(LIBMD_PSR_DIRS)
	-$(INS.slink6)

$(LIBMD_PSR64_DIRS):
	-$(INS.dir.root.bin)

$(LIBMD_PSR64_LINKS): $(LIBMD_PSR64_DIRS)
	-$(INS.slink64)

include $(SRC)/lib/Makefile.targ
