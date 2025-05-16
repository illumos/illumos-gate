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
# Copyright 2014 Joyent, Inc.
#

include		$(SRC)/Makefile.master

MANSECT=	4fs

MANFILES=	bootfs.4fs	\
		ctfs.4fs	\
		dcfs.4fs	\
		dev.4fs		\
		devfs.4fs	\
		fd.4fs		\
		hsfs.4fs	\
		hyprlofs.4fs	\
		lofs.4fs	\
		lxproc.4fs	\
		objfs.4fs	\
		pcfs.4fs	\
		sharefs.4fs	\
		smbfs.4fs	\
		tmpfs.4fs	\
		udfs.4fs	\
		ufs.4fs

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
