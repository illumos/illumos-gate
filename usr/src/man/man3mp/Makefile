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

MANSECT= 	3mp

MANFILES=	mp.3mp

MANLINKS=	mp_gcd.3mp	\
	 	mp_itom.3mp	\
	 	mp_madd.3mp	\
	 	mp_mcmp.3mp	\
	 	mp_mdiv.3mp	\
	 	mp_mfree.3mp	\
	 	mp_min.3mp	\
	 	mp_mout.3mp	\
	 	mp_msqrt.3mp	\
	 	mp_msub.3mp	\
	 	mp_mtox.3mp	\
	 	mp_mult.3mp	\
	 	mp_pow.3mp	\
	 	mp_rpow.3mp	\
	 	mp_sdiv.3mp	\
	 	mp_xtom.3mp

mp_gcd.3mp	:= LINKSRC = mp.3mp
mp_itom.3mp	:= LINKSRC = mp.3mp
mp_madd.3mp	:= LINKSRC = mp.3mp
mp_mcmp.3mp	:= LINKSRC = mp.3mp
mp_mdiv.3mp	:= LINKSRC = mp.3mp
mp_mfree.3mp	:= LINKSRC = mp.3mp
mp_min.3mp	:= LINKSRC = mp.3mp
mp_mout.3mp	:= LINKSRC = mp.3mp
mp_msqrt.3mp	:= LINKSRC = mp.3mp
mp_msub.3mp	:= LINKSRC = mp.3mp
mp_mtox.3mp	:= LINKSRC = mp.3mp
mp_mult.3mp	:= LINKSRC = mp.3mp
mp_pow.3mp	:= LINKSRC = mp.3mp
mp_rpow.3mp	:= LINKSRC = mp.3mp
mp_sdiv.3mp	:= LINKSRC = mp.3mp
mp_xtom.3mp	:= LINKSRC = mp.3mp

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
