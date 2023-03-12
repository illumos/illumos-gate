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
# Copyright (c) 2018, Joyent, Inc.
#

include ../Makefile.cmd

SUBDIRS= acpidump acpixtract iasl

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
_msg:=          TARGET= catalog


.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all:		$(SUBDIRS)

_msg:

install: $(SUBDIRS)

clean: $(SUBDIRS)

clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
