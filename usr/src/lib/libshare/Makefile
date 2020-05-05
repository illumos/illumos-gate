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
#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.lib

HDRS =		libshare.h libshare_impl.h scfutil.h
HDRDIR =	common

MACHS = $(MACH)
$(BUILD64)MACHS += $(MACH64)

# Add plugin module directories here. They need to build after the libshare
# objects are built.
PLUGINS =	nfs smb smbfs autofs
$(PLUGINS):	$(MACHS)

SUBDIRS =	$(MACHS) $(PLUGINS)

MSGFILES=	common/libshare.c common/libsharecore.c common/scfutil.c \
		common/plugin.c common/parser.c common/libshare_zfs.c
POFILE=		libshare.po

all :=		TARGET = all
clean :=	TARGET = clean
clobber	:=	TARGET = clobber
install	:=	TARGET = install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(POFILE):	$(MSGFILES)
	$(BUILDPO.msgfiles)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

_msg:	$(MSGDOMAINPOFILE)


FRC:

include ../Makefile.targ
include ../../Makefile.msg.targ
