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

SHELL=/usr/bin/ksh93

include		../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=		TARGET= _msg

.KEEP_STATE:

all clean clobber install _msg: $(SUBDIRS)

LIBRARY=	libdll.a

HDRS= \
	dlldefs.h

HDRDIR32= $(MACH)/src/lib/libdll
HDRDIR64= $(MACH64)/src/lib/libdll
include ../Makefile.asthdr

install_h: $(ROOTHDRS)

# We don't check these header files because they're owned by AT&T/AST
check:

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
