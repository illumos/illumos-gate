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
# Copyright (c) 2014, Joyent, Inc.  All rights reserved.
#

include		$(SRC)/Makefile.master

MANSECT=	3vnd

MANFILES=	vnd_create.3vnd 	\
		vnd_errno.3vnd 		\
		vnd_frameio_read.3vnd 	\
		vnd_pollfd.3vnd 	\
		vnd_prop_get.3vnd 	\
		vnd_prop_iter.3vnd 	\
		vnd_prop_writeable.3vnd	\
		vnd_walk.3vnd

MANLINKS=	frameio_t.3vnd		\
		framevec_t.3vnd		\
		vnd_close.3vnd		\
		vnd_frameio_write.3vnd	\
		vnd_open.3vnd 		\
		vnd_prop_set.3vnd	\
		vnd_prop_iter_f.3vnd	\
		vnd_strerror.3vnd	\
		vnd_strsyserror.3vnd	\
		vnd_syserrno.3vnd	\
		vnd_unlink.3vnd 	\
		vnd_walk_cb_f.3vnd

# vnd_create.3vnd
vnd_open.3vnd		:= LINKSRC = vnd_create.3vnd
vnd_unlink.3vnd		:= LINKSRC = vnd_create.3vnd
vnd_close.3vnd		:= LINKSRC = vnd_create.3vnd

# vnd_errno.3vnd
vnd_strerror.3vnd	:= LINKSRC = vnd_errno.3vnd
vnd_syserrno.3vnd	:= LINKSRC = vnd_errno.3vnd 
vnd_strsyserror.3vnd	:= LINKSRC = vnd_errno.3vnd 

# vnd_frameio_read.3vnd
vnd_frameio_write.3vnd	:= LINKSRC = vnd_frameio_read.3vnd 
framevec_t.3vnd		:= LINKSRC = vnd_frameio_read.3vnd
frameio_t.3vnd		:= LINKSRC = vnd_frameio_read.3vnd

# vnd_prop_get.3vnd
vnd_prop_set.3vnd	:= LINKSRC = vnd_prop_get.3vnd

# vnd_prop_iter.3vnd
vnd_prop_iter_f.3vnd	:= LINKSRC = vnd_prop_iter.3vnd

# vnd_walk.3vnd
vnd_walk_cb_f.3vnd	:= LINKSRC = vnd_walk.3vnd

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
