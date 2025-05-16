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
# Copyright 2023 Peter Tribble
#

include		$(SRC)/Makefile.master

MANSECT=	3ext

MANFILES=	NOTE.3ext			\
		SUNW_C_GetMechSession.3ext	\
		crypt.3ext			\
		demangle.3ext			\
		ecb_crypt.3ext			\
		efi_alloc_and_init.3ext		\
		ld_support.3ext			\
		md4.3ext			\
		md5.3ext			\
		read_vtoc.3ext			\
		rtld_audit.3ext			\
		rtld_db.3ext			\
		sendfile.3ext			\
		sendfilev.3ext			\
		sha1.3ext			\
		sha2.3ext			\
		stdarg.3ext			\
		varargs.3ext

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
