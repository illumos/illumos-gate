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

include $(SRC)/cmd/Makefile.cmd

.PARALLEL:

COMMON_SUBDIRS=		\
	filelist	\
	fiocompress	\
	scripts		\
	bootadm

i386_SUBDIRS=		\
	installgrub	\
	mbr		\
	symdef

COMMON_LINTSUBDIRS=	\
	bootadm	

i386_LINTSUBDIRS=	\
	fiocompress	\
	installgrub	\
	symdef

COMMON_MSGSUBDIRS=	\
	bootadm		\
	fiocompress

i386_MSGSUBDIRS=	\
	installgrub


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
