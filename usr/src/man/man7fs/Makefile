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
# Copyright 2011 Nexenta Systems, Inc. All rights reserved.
# Copyright 2012 Joyent, Inc. All rights reserved.
#

include ../../Makefile.master

MANSECT = 	7fs

MANFILES = 	ctfs.7fs	\
	 	dcfs.7fs	\
	 	dev.7fs		\
	 	devfs.7fs	\
		fd.7fs		\
	 	hsfs.7fs	\
	 	hyprlofs.7fs	\
	 	lofs.7fs	\
	 	objfs.7fs	\
	 	pcfs.7fs	\
	 	sharefs.7fs	\
	 	smbfs.7fs	\
	 	tmpfs.7fs	\
	 	udfs.7fs	\
	 	ufs.7fs

MANSOFILES =	stderr.7fs	\
		stdin.7fs	\
		stdout.7fs

MANFILES +=	$(MANSOFILES)

stderr.7fs	:= SOSRC = man7fs/fd.7fs
stdin.7fs	:= SOSRC = man7fs/fd.7fs
stdout.7fs	:= SOSRC = man7fs/fd.7fs

.KEEP_STATE:

include ../Makefile.man

install: $(ROOTMANFILES)
