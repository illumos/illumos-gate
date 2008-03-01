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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include		../Makefile.lib
include		Makefile.openssl

SUBDIRS =	libcrypto \
		libssl

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
install_h :=	TARGET= install_h
lint :=		TARGET= lint

HDRS=		e_os2.h

HDRDIR=		$(OPENSSL_SRC)

ROOTHDRDIR=	$(ROOTSFWINCLUDE)/openssl

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS) $(SUBDIRS)

#
# We don't check these header files because they're third-party swill.
#
check:

libssl: libcrypto

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

$(ROOTHDRS): $(ROOTHDRDIR)

$(ROOTHDRDIR): $(ROOTSFW)
	$(INS.dir)

include ../Makefile.targ
