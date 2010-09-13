#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#

PROG= mklocale

include ../Makefile.cmd

SUBDIRS = ctype collate messages monetary numeric time

all:=		TARGET=	all
install:=	TARGET=	install
clean:=		TARGET=	clean
clobber:=	TARGET= clobber
lint:=		TARGET=	lint
check:=		TARGET=	check

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all clean install lint check clobber: $(SUBDIRS)

# We don't deliver any programs, so we don't deliver messaging
# data for them either.
_msg:

$(SUBDIRS):	FRC
	cd $@; pwd; $(MAKE) $(TARGET)

FRC:
