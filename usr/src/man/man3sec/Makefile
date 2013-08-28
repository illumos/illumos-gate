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

MANSECT= 	3sec

MANFILES= 	acl_check.3sec		\
	 	acl_free.3sec		\
	 	acl_get.3sec		\
	 	acl_strip.3sec		\
	 	acl_totext.3sec		\
	 	acl_trivial.3sec	\
	 	aclcheck.3sec		\
	 	aclsort.3sec		\
	 	acltomode.3sec		\
	 	acltotext.3sec

MANLINKS=	acl_fromtext.3sec	\
		acl_set.3sec		\
		aclfrommode.3sec	\
		aclfromtext.3sec	\
		facl_get.3sec		\
		facl_set.3sec

acl_set.3sec		:= LINKSRC = acl_get.3sec
facl_get.3sec		:= LINKSRC = acl_get.3sec
facl_set.3sec		:= LINKSRC = acl_get.3sec

acl_fromtext.3sec	:= LINKSRC = acl_totext.3sec

aclfrommode.3sec	:= LINKSRC = acltomode.3sec

aclfromtext.3sec	:= LINKSRC = acltotext.3sec

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
