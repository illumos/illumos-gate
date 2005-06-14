#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include		../Makefile.lib
include		Makefile.openssl

# EXPORT DELETE START
SUBDIRS =	libcrypto \
		libcrypto_extra \
		libssl \
		libssl_extra
# EXPORT DELETE END

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
install_h :=	TARGET= install_h
lint :=		TARGET= lint

HDRS=		e_os2.h

HDRDIR=		$(OPENSSL_SRC)

# EXPORT DELETE START
ROOTHDRDIR=	$(ROOTSFWINCLUDE)/openssl
# EXPORT DELETE END

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS) $(SUBDIRS)

#
# We don't check these header files because they're third-party swill.
#
check:

libssl: libcrypto
libcrypto_extra: libcrypto

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

$(ROOTHDRS): $(ROOTHDRDIR)

$(ROOTHDRDIR): $(ROOTSFW)
	$(INS.dir)

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) Makefile+
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(RM) Makefile
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile

# EXPORT DELETE END		

include ../Makefile.targ
