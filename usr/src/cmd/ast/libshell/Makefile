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
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

SHELL= /usr/bin/ksh93

include		$(SRC)/lib/Makefile.lib

SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
install_h :=	TARGET= install_h
_msg :=		TARGET= _msg
_feature :=	TARGET= _feature

.KEEP_STATE:
.PARALLEL: $(SUBDIRS)

all clean clobber install _feature: $(SUBDIRS)
_msg: $(MACH)

include Makefile.defs
HDRS= $(HEADERINSTALL)
HDRDIR32= $(MACH)/ast
HDRDIR64= $(MACH64)/ast
include ../Makefile.asthdr

install_h: $(SUBDIRS) .WAIT $(ROOTHDRS)
install: install_h

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)
FRC:

ASTSRC= $(CONTRIB)/ast/src/cmd/ksh93
include Makefile.tests

include $(SRC)/lib/Makefile.targ
