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
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
#

file path=usr/share/man/man3malloc/bsdmalloc.3malloc
file path=usr/share/man/man3malloc/malloc.3malloc
file path=usr/share/man/man3malloc/mapmalloc.3malloc
file path=usr/share/man/man3malloc/mtmalloc.3malloc
file path=usr/share/man/man3malloc/umem_alloc.3malloc
file path=usr/share/man/man3malloc/umem_cache_create.3malloc
file path=usr/share/man/man3malloc/umem_debug.3malloc
file path=usr/share/man/man3malloc/watchmalloc.3malloc
link path=usr/share/man/man3malloc/calloc.3malloc target=malloc.3malloc
link path=usr/share/man/man3malloc/free.3malloc target=malloc.3malloc
link path=usr/share/man/man3malloc/mallinfo.3malloc target=malloc.3malloc
link path=usr/share/man/man3malloc/mallocctl.3malloc target=mtmalloc.3malloc
link path=usr/share/man/man3malloc/mallopt.3malloc target=malloc.3malloc
link path=usr/share/man/man3malloc/memalign.3malloc target=malloc.3malloc
link path=usr/share/man/man3malloc/realloc.3malloc target=malloc.3malloc
link path=usr/share/man/man3malloc/umem_cache_alloc.3malloc \
    target=umem_cache_create.3malloc
link path=usr/share/man/man3malloc/umem_cache_destroy.3malloc \
    target=umem_cache_create.3malloc
link path=usr/share/man/man3malloc/umem_cache_free.3malloc \
    target=umem_cache_create.3malloc
link path=usr/share/man/man3malloc/umem_free.3malloc target=umem_alloc.3malloc
link path=usr/share/man/man3malloc/umem_nofail_callback.3malloc \
    target=umem_alloc.3malloc
link path=usr/share/man/man3malloc/umem_zalloc.3malloc \
    target=umem_alloc.3malloc
link path=usr/share/man/man3malloc/valloc.3malloc target=malloc.3malloc
