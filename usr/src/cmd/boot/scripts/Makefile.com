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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
# 

.SUFFIXES: .ksh

MANIFEST= boot-archive-update.xml
SVCMETHOD= boot-archive-update

sparc_BOOTPROG=

i386_BOOTPROG=			\
	create_diskmap		\
	update_grub

COMMON_BOOTPROG=		\
	create_ramdisk		\
	extract_boot_filelist


BOOTPROG= $(COMMON_BOOTPROG) $($(MACH)_BOOTPROG)
METHODPROG= boot-archive-update
PROG= root_archive

include ../Makefile.com

ROOTMANIFESTDIR= $(ROOTSVCSYSTEM)
$(ROOTMANIFEST) := FILEMODE= 444

ROOTBOOTSOLARISUSRSBINLINKS= $(PROG:%=$(ROOTBOOTSOLARISBIN)/%)

.KEEP_STATE:

all: $(BOOTPROG) $(METHODPROG) $(PROG)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(BOOTPROG) $(METHODPROG) $(PROG)

lint _msg:

$(ROOTBOOTSOLARISUSRSBINLINKS):
	$(RM) $@; $(SYMLINK) ../../../usr/sbin/$(@F) $@

# Default rule for building ksh scripts.
.ksh:
	$(RM) $@
	$(CAT) $< > $@
	$(CHMOD) +x $@

include ../Makefile.targ
