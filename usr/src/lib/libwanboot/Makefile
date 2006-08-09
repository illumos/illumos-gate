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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/lib/Makefile.lib

SUBDIRS	=	$(MACH)

HDRS =		boot_http.h \
		bootinfo.h \
		bootlog.h \
		netboot_paths.h \
		parseURL.h \
		p12aux.h \
		p12access.h\
		p12err.h\
		wanboot_conf.h
HDRDIR =	$(SRCDIR) $(SRC)/common/net/wanboot

CHECKHDRS +=	$(SRC)/common/net/wanboot/auxutil.h

POFILE =	libwanboot.po
MSGFILES =	$(SRC)/common/net/wanboot/bootconf_errmsg.c \
		$(SRC)/common/net/wanboot/boot_http.c \
		$(SRC)/common/net/wanboot/bootlog.c \
		$(SRC)/common/net/wanboot/http_errorstr.c \
		$(SRC)/common/net/wanboot/p12err.c
XGETFLAGS =	-a -x libwanboot.xcl

all := 		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install	:=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(POFILE):	pofile_MSGFILES

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ
