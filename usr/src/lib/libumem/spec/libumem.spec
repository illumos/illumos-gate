#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#malloc interface
function	malloc extends libc/spec/gen.spec malloc
version		SUNW_1.1
binding		nodirect
end

function	calloc extends libc/spec/gen.spec calloc
version		SUNW_1.1
binding		nodirect
end

function	memalign extends libc/spec/gen.spec memalign
version		SUNW_1.1
binding		nodirect
end

function	valloc extends libc/spec/gen.spec valloc
version		SUNW_1.1
binding		nodirect
end

function	free extends libc/spec/gen.spec free
version		SUNW_1.1
binding		nodirect
end

function	realloc extends libc/spec/gen.spec realloc
version		SUNW_1.1
binding		nodirect
end

#umem_alloc interface
function	umem_alloc
include		<umem.h>
declaration	void *umem_alloc(size_t size, int flags);
version		SUNW_1.1
end

function	umem_alloc_align
include		<umem.h>
declaration	void *umem_alloc_align(size_t size, size_t align, int flags);
version		SUNWprivate_1.1
end

function	umem_zalloc
include		<umem.h>
declaration	void *umem_zalloc(size_t size, int flags);
version		SUNW_1.1
end

function	umem_free
include		<umem.h>
declaration	void umem_free(void *buf, size_t size);
version		SUNW_1.1
end

function	umem_free_align
include		<umem.h>
declaration	void umem_free_align(void *buf, size_t size);
version		SUNWprivate_1.1
end

#Cache manipulation and allocation
function	umem_cache_create
include		<umem.h>
declaration	umem_cache_t *umem_cache_create(char *debug_name, size_t bufsize, size_t align, umem_constructor_t *constructor, umem_destructor_t *destructor, umem_reclaim_t *reclaim, void *callback_data, vmem_t *source, int cflags);
version		SUNW_1.1
errno		ENOMEM EAGAIN EINVAL
exception	$return == 0
end

function	umem_cache_destroy
include		<umem.h>
declaration	void umem_cache_destroy(umem_cache_t *cache);
version		SUNW_1.1
end

function	umem_cache_alloc
include		<umem.h>
declaration	void *umem_cache_alloc(umem_cache_t *cache, int flags);
version		SUNW_1.1
end

function	umem_cache_free
include		<umem.h>
declaration	void umem_cache_free(umem_cache_t *cache, void *buffer);
version		SUNW_1.1
end

#misc
function	umem_nofail_callback
include		<umem.h>
declaration	void umem_nofail_callback(umem_nofail_callback_t *callback);
version		SUNW_1.1
end

#misc -- private
function	umem_reap
version		SUNWprivate_1.1
end

#vmem interface
function	vmem_create
version		SUNWprivate_1.1
end

function	vmem_destroy
version		SUNWprivate_1.1
end

function	vmem_alloc
version		SUNWprivate_1.1
end

function	vmem_xalloc
version		SUNWprivate_1.1
end

function	vmem_free
version		SUNWprivate_1.1
end

function	vmem_xfree
version		SUNWprivate_1.1
end

function	vmem_add
version		SUNWprivate_1.1
end

function	vmem_contains
version		SUNWprivate_1.1
end

function	vmem_walk
version		SUNWprivate_1.1
end

function	vmem_size
version		SUNWprivate_1.1
end

function	vmem_heap_arena
version		SUNWprivate_1.1
end
