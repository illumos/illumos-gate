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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

include ../../Makefile.lib

HDRS =	mms.h           \
	mms_api_msg.h   \
	mms_err.h       \
	mms_network.h   \
	mms_strapp.h    \
	mms_trace.h     \
	mms_api.h       \
	mms_cat.h       \
	mms_dmd.h       \
	mms_list.h      \
	mms_parser.h    \
	mms_sym.h


HDRDIR =        $(SRC)/common/mms/mms
SUBDIRS	=	$(MACH)

POFILE = mms.po
MSGFILES = common/mms_cat.i
CLEANFILES += $(MSGFILES)

ROOTLIBDIR =    $(ROOT)/usr/lib
ROOTHDRDIR=     $(ROOT)/usr/include/mms
ROOTDIRS =      $(ROOTLIBDIR) $(ROOTHDRDIR)

# C preprocessor flags used to build message catalog:
#	- Include message header file directories.
#	- Don't redefine gettext for message catalog generation.
CPPFLAGS +=     -I$(SRCDIR) -I$(SRC)/common/mms/mms -DMMS_CAT

all := 		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install	:=	TARGET = install
lint :=		TARGET = lint

.KEEP_STATE:

all clean clobber lint: $(SUBDIRS)

install: $(ROOTDIRS) $(SUBDIRS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS)

check: $(CHECKHDR)

$(ROOTDIRS):
	$(INS.dir)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include ../../Makefile.targ
