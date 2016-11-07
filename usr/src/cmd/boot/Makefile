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
# Copyright 2016 Toomas Soome <tsoome@me.com>
# Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
#

include $(SRC)/cmd/Makefile.cmd

.PARALLEL:

COMMON_SUBDIRS=		\
	filelist	\
	fiocompress	\
	scripts		\
	bootadm		\
	installboot

i386_SUBDIRS=		\
	installgrub	\
	mbr		\
	symdef

sparc_SUBDIRS=

COMMON_LINTSUBDIRS=	\
	bootadm		\
	installboot

i386_LINTSUBDIRS=	\
	fiocompress	\
	installgrub	\
	symdef

sparc_LINTSUBDIRS=

COMMON_MSGSUBDIRS=	\
	bootadm		\
	fiocompress	\
	installboot

i386_MSGSUBDIRS=	\
	installgrub

sparc_MSGSUBDIRS=


all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=		TARGET= _msg

.KEEP_STATE:

SUBDIRS = $(COMMON_SUBDIRS) $($(MACH)_SUBDIRS)
LINTSUBDIRS = $(COMMON_LINTSUBDIRS) $($(MACH)_LINTSUBDIRS)
MSGSUBDIRS = $(COMMON_MSGSUBDIRS) $($(MACH)_MSGSUBDIRS)

all clean clobber: $(SUBDIRS)

install: $(SUBDIRS)

lint: $(LINTSUBDIRS)

_msg: $(MSGSUBDIRS)

FRC:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)
