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

include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/openssl/Makefile.openssl
include $(SRC)/lib/Makefile.rootfs

VERS =		.$(OPENSSL_VERSION)

CPPFLAGS =	$(OPENSSL_BUILD_CPPFLAGS) $(CPPFLAGS.master)

COPTFLAG =   -xO5
sparcv9_COPTFLAG =	-xO5

#
# Ensure `all' is the default target.
#
all:

# Normally ROOTLIBPCDIR would be expressed in terms of ROOTLIBDIR
# however it should always be /usr/lib/pkgconfig so we can't do that here
# because ROOTLIBDIR is actually ROOTFS_LIBDIR.
# LIBPCSRC could be expressed in terms of LIBNAME in some cases but
# not this one because the libraries are libcrypto and libssl but the
# expected .pc file is openssl.pc
#
# The 64 bit directory isn't where one would normally expect but this is
# what is documented in pkg-config(1) and it is also where all the
# existing sparcv9 pkgconfig files are.

LIBPCDIR =	/usr/lib/pkgconfig
LIBPCDIR64 =	/usr/lib/$(MACH64)/pkgconfig
LIBPCSRC =	openssl.pc

OPENSSL_PREFIX = /usr
$(LIBPCSRC): ../../$(LIBPCSRC).tmpl
	$(SED)	-e s@__VERSION__@$(OPENSSL_VERSION)@ \
		-e s@__PREFIX__@$(OPENSSL_PREFIX)@ \
		-e s@__LIBDIR__@$(OPENSSL_LIBDIR)@ \
		 < ../../$(LIBPCSRC).tmpl > $(LIBPCSRC)

ROOTLIBPCDIR =	$(ROOT)/$(LIBPCDIR)
ROOTLIBPC =	$(LIBPCSRC:%=$(ROOTLIBPCDIR)/%)

ROOTLIBPCDIR64 = $(ROOT)/$(LIBPCDIR64)
ROOTLIBPC64 =	$(LIBPCSRC:%=$(ROOTLIBPCDIR64)/%)

$(ROOTLIBPCDIR):
	$(INS.dir)

$(ROOTLIBPCDIR)/%: $(ROOTLIBPCDIR) %
	$(INS.file)

$(ROOTLIBPCDIR64):
	$(INS.dir)

$(ROOTLIBPCDIR64)/%: $(ROOTLIBPCDIR64) %
	$(INS.file)
