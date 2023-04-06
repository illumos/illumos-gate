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

#
# Note we build a native version of libscf.so.1 out of tools/svc.
#

include		../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
install :=      TARGET= install

HDRDIR =	inc
HDRS =		libscf.h libscf_priv.h

#
# only error descriptions and templates messages are internationalized,
# but they aren't directly surrounded by gettext(), so we use '-a' to grab
# all strings.
#
MSGFILES =	common/error.c common/scf_tmpl.c
POFILE =	libscf.po
XGETFLAGS +=	-a

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

$(POFILE):	pofile_MSGFILES

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
include ../../Makefile.msg.targ
