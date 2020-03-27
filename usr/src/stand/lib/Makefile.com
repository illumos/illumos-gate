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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Common macro definitions and pattern rules for stand libraries.
# Basically just a trivial wrapper around $(SRC)/lib/Makefile.lib.
#

include $(SRC)/lib/Makefile.lib
include $(SRC)/stand/lib/Makefile.$(MACH)

SRCDIR =	.
LIBS +=		$(LIBRARY)
CFLAGS +=	$(CCVERBOSE)
LDFLAGS =	-r
LDLIBS +=	-lsa

#
# Reset ROOTLIBDIR to an alternate directory so that we don't clash with
# $(ROOT)/usr/lib.  The Makefiles over in usr/src/psm expect to find our
# libraries here.
#
ROOTLIBDIR = $(ROOT)/stand/lib

#
# Paths to a variety of commonly-referenced directories.  Note that we use
# relative paths so that references to filenames in the source (e.g.,
# through use of assert()) are not exposed absolutely (for reasons of
# taste and to help make the binaries end up the same even when built from
# different workspaces).  Makefiles that are more than one directory level
# deeper than this Makefile need to set DIRREL appropriately so that the
# relative paths can still be accessed correctly.
#
TOPDIR =	$(DIRREL)../../..
STANDDIR =	$(DIRREL)../..
CMNNETDIR =	$(TOPDIR)/common/net
SYSDIR	=	$(TOPDIR)/uts

#
# As a courtesy to the numerous standalone libraries which are built from
# sources living elsewhere, we provide a generic CMNDIR macro which the
# library's Makefile can set (if need be) to the primary other directory
# it grabs its sources from.
#
CMNDIR =	.

#
# Configure the appropriate #defines and #include path for building
# standalone bits.  Note that we turn off access to /usr/include and
# the proto area since those headers match libc's implementation, and
# libc is of course not available to standalone binaries.
#
CPPDEFS	=	-D$(KARCH) -D_BOOT -D_KERNEL -D_MACHDEP
CPPINCS	=	-YI,$(STANDDIR)/lib/sa -I$(STANDDIR)/lib/sa \
		-I$(STANDDIR) -I$(SRCDIR) -I$(CMNDIR) \
		-I$(STANDDIR)/$(MACH) -I$(SYSDIR)/common $(ARCHDIRS) \
		-I$(SYSDIR)/sun4 -I$(SYSDIR)/$(KARCH)

CPPFLAGS =	$(CPPDEFS) $(CPPINCS)
AS_CPPFLAGS =	$(CPPDEFS) $(CPPINCS:-YI,%=-I%)
ASFLAGS =	-P -D__STDC__ -D_ASM

#
# While things are pretty much 32-bit lint-clean, there are a ton of
# suspect pointer casts.  Since these may be serious problems (especially
# on SPARC), this really needs to be investigated thoroughly one day.
# However, we shouldn't feel too bad: the whole kernel is linted with this
# turned off as well (along with a dozen other disabled warnings).
#
# The other two -erroff's are needed only because lint's -u flag is lame
# and also turns off "name used but not defined" checks (so we instead
# just enumerate the errors that -u turns off that we want turned off).
#
LINTFLAGS = -nmsF -erroff=E_BAD_PTR_CAST_ALIGN \
	    -erroff=E_NAME_DECL_NOT_USED_DEF2 -erroff=E_NAME_DEF_NOT_USED2 \
	    -erroff=E_STATIC_UNUSED

#
# CPPFLAGS values that *must* be included whenever linking with or
# building libssl or libcrypto.
# Exclusions here are for both legal and size reasons.
#
OPENSSL_SRC = ../../../common/openssl
OPENSSL_BUILD_CPPFLAGS_sparc = -DB_ENDIAN
OPENSSL_BUILD_CPPFLAGS = -DOPENSSL_NO_ECDH -DOPENSSL_NO_ECDSA \
			-DOPENSSL_NO_HW_4758_CCA -DOPENSSL_NO_HW_AEP \
			-DOPENSSL_NO_HW_ATALLA -DOPENSSL_NO_HW_CHIL \
			-DOPENSSL_NO_HW_CSWIFT -DOPENSSL_NO_HW_GMP \
			-DOPENSSL_NO_HW_NURON -DOPENSSL_NO_HW_PADLOCK \
			-DOPENSSL_NO_HW_SUREWARE -DOPENSSL_NO_HW_UBSEC \
			-DOPENSSL_NO_HW \
			-DOPENSSL_NO_MD2 -DOPENSSL_NO_MD4 -DOPENSSL_NO_MDC2 \
			-DOPENSSL_NO_RIPEMD -DOPENSSL_NO_RC3 -DOPENSSL_NO_RC4 \
			-DOPENSSL_NO_EC -DOPENSSL_NO_RC5 -DOPENSSL_NO_IDEA \
			-DOPENSSL_NO_CAST -DOPENSSL_NO_AES \
			-DDEVRANDOM=\"/dev/urandom\" \
			-I.. \
			$(OPENSSL_BUILD_CPPFLAGS_$(MACH)) \
			-I$(ROOT)/usr/include \
			-I$(OPENSSL_SRC) -I$(OPENSSL_SRC)/crypto

#
# CPPFLAGS values that *must* be included whenever linking the DHCP
# routines in $SRC/common/net/dhcp.
#
DHCPCPPFLAGS = -I$(CMNNETDIR)/dhcp

#
# CPPFLAGS values that *must* be included whenever linking with or
# building libsock.
#
# The header files for libsock provide alternate definitions for data
# types that are also defined in <sys/stream.h>.  To make sure we get the
# right ones, prevent <sys/stream.h>'s contents from being included.  This
# is shameful.
#
SOCKCPPFLAGS = -I$(STANDDIR)/lib/sock -D_SYS_STREAM_H

.KEEP_STATE:
