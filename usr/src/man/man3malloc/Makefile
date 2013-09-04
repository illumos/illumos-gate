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

MANSECT= 	3malloc

MANFILES= 	bsdmalloc.3malloc		\
		malloc.3malloc			\
		mapmalloc.3malloc		\
		mtmalloc.3malloc		\
		umem_alloc.3malloc		\
		umem_cache_create.3malloc	\
		umem_debug.3malloc		\
		watchmalloc.3malloc

MANLINKS=	calloc.3malloc			\
		free.3malloc			\
		mallinfo.3malloc		\
		mallocctl.3malloc		\
		mallopt.3malloc			\
		memalign.3malloc		\
		realloc.3malloc			\
		umem_cache_alloc.3malloc	\
		umem_cache_destroy.3malloc	\
		umem_cache_free.3malloc		\
		umem_free.3malloc		\
		umem_nofail_callback.3malloc	\
		umem_zalloc.3malloc		\
		valloc.3malloc

calloc.3malloc			:= LINKSRC = malloc.3malloc
free.3malloc			:= LINKSRC = malloc.3malloc
mallinfo.3malloc		:= LINKSRC = malloc.3malloc
mallopt.3malloc			:= LINKSRC = malloc.3malloc
memalign.3malloc		:= LINKSRC = malloc.3malloc
realloc.3malloc			:= LINKSRC = malloc.3malloc
valloc.3malloc			:= LINKSRC = malloc.3malloc

mallocctl.3malloc		:= LINKSRC = mtmalloc.3malloc

umem_free.3malloc		:= LINKSRC = umem_alloc.3malloc
umem_nofail_callback.3malloc	:= LINKSRC = umem_alloc.3malloc
umem_zalloc.3malloc		:= LINKSRC = umem_alloc.3malloc

umem_cache_alloc.3malloc	:= LINKSRC = umem_cache_create.3malloc
umem_cache_destroy.3malloc	:= LINKSRC = umem_cache_create.3malloc
umem_cache_free.3malloc		:= LINKSRC = umem_cache_create.3malloc

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(ROOTMANLINKS)
