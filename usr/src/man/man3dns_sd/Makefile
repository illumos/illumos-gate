#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3dns_sd

MANFILES=	DNSServiceBrowse.3dns_sd		\
		DNSServiceConstructFullName.3dns_sd	\
		DNSServiceCreateConnection.3dns_sd	\
		DNSServiceEnumerateDomains.3dns_sd	\
		DNSServiceProcessResult.3dns_sd		\
		DNSServiceQueryRecord.3dns_sd		\
		DNSServiceReconfirmRecord.3dns_sd	\
		DNSServiceRefDeallocate.3dns_sd		\
		DNSServiceRefSockFD.3dns_sd		\
		DNSServiceRegister.3dns_sd		\
		DNSServiceResolve.3dns_sd		\
		TXTRecordCreate.3dns_sd

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
