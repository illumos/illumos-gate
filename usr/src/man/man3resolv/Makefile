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

MANSECT= 	3resolv

MANFILES=	resolver.3resolv

MANLINKS=	dn_comp.3resolv			\
	 	dn_expand.3resolv		\
	 	fp_resstat.3resolv		\
	 	herror.3resolv			\
	 	hstrerror.3resolv		\
	 	res_getservers.3resolv		\
	 	res_hostalias.3resolv		\
	 	res_init.3resolv		\
	 	res_mkquery.3resolv		\
	 	res_nclose.3resolv		\
	 	res_ndestroy.3resolv		\
	 	res_ninit.3resolv		\
	 	res_nmkquery.3resolv		\
	 	res_nquery.3resolv		\
	 	res_nquerydomain.3resolv	\
	 	res_nsearch.3resolv		\
	 	res_nsend.3resolv		\
	 	res_nsendsigned.3resolv		\
	 	res_query.3resolv		\
	 	res_search.3resolv		\
	 	res_send.3resolv		\
	 	res_setservers.3resolv

dn_comp.3resolv			:= LINKSRC = resolver.3resolv
dn_expand.3resolv		:= LINKSRC = resolver.3resolv
fp_resstat.3resolv		:= LINKSRC = resolver.3resolv
herror.3resolv			:= LINKSRC = resolver.3resolv
hstrerror.3resolv		:= LINKSRC = resolver.3resolv
res_getservers.3resolv		:= LINKSRC = resolver.3resolv
res_hostalias.3resolv		:= LINKSRC = resolver.3resolv
res_init.3resolv		:= LINKSRC = resolver.3resolv
res_mkquery.3resolv		:= LINKSRC = resolver.3resolv
res_nclose.3resolv		:= LINKSRC = resolver.3resolv
res_ndestroy.3resolv		:= LINKSRC = resolver.3resolv
res_ninit.3resolv		:= LINKSRC = resolver.3resolv
res_nmkquery.3resolv		:= LINKSRC = resolver.3resolv
res_nquery.3resolv		:= LINKSRC = resolver.3resolv
res_nquerydomain.3resolv	:= LINKSRC = resolver.3resolv
res_nsearch.3resolv		:= LINKSRC = resolver.3resolv
res_nsend.3resolv		:= LINKSRC = resolver.3resolv
res_nsendsigned.3resolv		:= LINKSRC = resolver.3resolv
res_query.3resolv		:= LINKSRC = resolver.3resolv
res_search.3resolv		:= LINKSRC = resolver.3resolv
res_send.3resolv		:= LINKSRC = resolver.3resolv
res_setservers.3resolv		:= LINKSRC = resolver.3resolv

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
