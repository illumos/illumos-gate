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

RELEASECERTS =		SUNW_SunOS_5.10
RELEASECRYPTO =		SUNW_SunOS_5.10 \
			SUNW_SunOS_5.11_Limited

ETCCRYPTOFILES = \
	kcf.conf \
	pkcs11.conf \
	$(RELEASECRYPTO:%=certs/%) \
	certs/CA

ETCCERTSFILES = \
	$(RELEASECERTS) \
	SUNWSolarisCA

include ../../Makefile.cmd

.KEEP_STATE:

ROOTCRYPTODIR=		$(ROOT)/etc/crypto
ROOTCRYPTOCERTSDIR=	$(ROOTCRYPTODIR)/certs

ROOTETCCERTSDIR=	$(ROOT)/etc/certs

$(ROOTCRYPTODIR):=	OWNER= root
$(ROOTCRYPTODIR):=	GROUP= sys
$(ROOTETCCERTSDIR):=	OWNER= root
$(ROOTETCCERTSDIR):=	GROUP= sys

IETCCRYPTOFILES=	$(ETCCRYPTOFILES:%=$(ROOTCRYPTODIR)/%)
IETCCERTSFILES=		$(ETCCERTSFILES:%=$(ROOTETCCERTSDIR)/%)

$(ROOTCRYPTODIR)/%:	%
			$(INS.file)
$(RELEASECRYPTO:%=$(ROOTCRYPTODIR)/certs/%): \
			certs/$(@F:SUNW_SunOS_5.%=SUNWCryptographic%)
			$(RM) $@
			$(INS) -s -m $(FILEMODE) -f $(@D) \
				certs/$(@F:SUNW_SunOS_5.%=SUNWCryptographic%)
			$(MV) $(@D)/$(@F:SUNW_SunOS_5.%=SUNWCryptographic%) $@

$(ROOTETCCERTSDIR)/%:	certs/%
			$(INS.file)
$(RELEASECERTS:%=$(ROOTETCCERTSDIR)/%): \
			certs/$(@F:SUNW_SunOS_5.%=SUNWSolaris%)
			$(RM) $@
			$(INS) -s -m $(FILEMODE) -f $(@D) \
				certs/$(@F:SUNW_SunOS_5.%=SUNWSolaris%)
			$(MV) $(@D)/$(@F:SUNW_SunOS_5.%=SUNWSolaris%) $@

$(IETCCRYPTOFILES):=	FILEMODE= 644
$(IETCCRYPTOFILES):=	OWNER= root
$(IETCCRYPTOFILES):=	GROUP= sys
$(IETCCERTSFILES):=	FILEMODE= 644
$(IETCCERTSFILES):=	OWNER= root
$(IETCCERTSFILES):=	GROUP= sys

install:	$(IETCCRYPTOFILES) $(IETCCERTSFILES)
