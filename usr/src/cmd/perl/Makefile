#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
#
# Copyright (c) 2014 Racktop Systems.
#

include $(SRC)/cmd/Makefile.cmd

SUBDIRS = \
	contrib/Sun/Solaris/BSM \
	contrib/Sun/Solaris/Intrs \
	contrib/Sun/Solaris/Kstat \
	contrib/Sun/Solaris/Lgrp \
	contrib/Sun/Solaris/Pg \
	contrib/Sun/Solaris/Project \
	contrib/Sun/Solaris/Task \
	contrib/Sun/Solaris/Utils

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber

all install clean clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
