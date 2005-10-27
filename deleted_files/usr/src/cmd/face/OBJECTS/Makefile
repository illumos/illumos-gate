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
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/OBJECTS/Makefile

include		../../Makefile.cmd
include		../src/Makefile.com

SUBDIRS=	dos mail spell programs pref lp

all:=		TARGET= all
install:=	TARGET= install

ROOTDIR=	$(ROOTVMSYS)/OBJECTS

OBJFILES=	Text.spell Text.show Text.mfhelp Text.merror Text.help Text.h \
		Text.exit Text.disp \
		Menu.waste Menu.users Menu.remove Menu.programs Menu.print \
		Menu.office Menu.mail Menu.h6.list Menu.h0.toc Menu.find \
		Menu.face Menu.create \
		Form.spell Form.send Form.sec Form.prin Form.org Form.find

ROOTBIN=	$(OBJFILES:%=$(ROOTDIR)/%)

FILEMODE=	755

# install rules

$(ROOTDIR)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(OBJFILES) $(SUBDIRS)

install: all $(ROOTDIR) $(ROOTBIN) $(SUBDIRS)

$(ROOTDIR):
	-$(INS.dir)

clean clobber lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
