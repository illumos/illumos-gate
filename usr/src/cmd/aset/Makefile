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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1991 by Sun Microsystems, Inc.
#
# cmd/aset/Makefile

PROG= aset.restore aset asetenv

FILES= tune.high tune.low tune.med uid_aliases

MASTERSFILES= $(FILES:%=masters/%)

SUBDIRS = util tasks

include ../Makefile.cmd

DIRMODE= 700
FILEMODE= 700
OWNER= root

# macros used by install
ROOTASET= $(ROOT)/usr/aset
ASETDIRS= archives masters reports tasks tmp util
ROOTDIRS= $(ROOTASET) $(ASETDIRS:%=$(ROOTASET)/%)
ROOTFILES= $(FILES:%=$(ROOTASET)/masters/%)
ROOTPROG= $(PROG:%=$(ROOTASET)/%)

# conditional assignments
all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint

$(ROOTFILES) := FILEMODE= 600

# install rules
$(ROOTASET)/masters/%: masters/%
	$(INS.file)

$(ROOTASET)/%: %
	$(INS.file)

.KEEP_STATE:

all: $(PROG) $(MASTERSFILES) $(SUBDIRS)

clean lint: $(SUBDIRS)

install: $(PROG) $(ROOTDIRS) $(ROOTPROG) $(ROOTFILES) $(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) $(PROG)

$(ROOTDIRS):
	$(INS.dir)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
