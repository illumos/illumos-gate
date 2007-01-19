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

PROG= create_ramdisk create_diskmap update_grub
METHODPROG= boot-archive-update
SBINPROG= root_archive

SBINLINKS= $(SBINPROG)

include ../Makefile.com

ROOTSBINPROG=	$(SBINPROG:%=$(ROOTUSRSBIN)/%)

ROOTMANIFESTDIR= $(ROOTSVCSYSTEM)
$(ROOTMANIFEST) := FILEMODE= 444

ROOTBOOTSOLARISBINLINKS= $(SBINLINKS:%=$(ROOTBOOTSOLARISBIN)/%)

.KEEP_STATE:

all: $(PROG) $(METHODPROG) $(SBINPROG)

$(ROOTBOOTSOLARISBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../../usr/sbin/$(@F) $@

check:	$(CHKMANIFEST)

clean:
	$(RM) $(PROG) $(METHODPROG) $(SBINPROG)

 _msg:

lint:

# Default rule for building ksh scripts.
.ksh:
	$(RM) $@
	$(CAT) $< > $@
	$(CHMOD) +x $@

include ../Makefile.targ
