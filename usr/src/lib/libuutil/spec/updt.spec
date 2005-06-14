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
#ident	"%Z%%M%	%I%	%E% SMI"
#

#
# list functions
#

function	uu_list_pool_create
include		<libuutil.h>
declaration	uu_list_pool_t *uu_list_pool_create(const char *, \
		    size_t, size_t, uu_compare_fn_t, uint32_t);
version		SUNWprivate_1.1
end

function	uu_list_pool_destroy
include		<libuutil.h>
declaration	void uu_list_pool_destroy(uu_list_pool_t *);
version		SUNWprivate_1.1
end

function	uu_list_node_init
include		<libuutil.h>
declaration	void uu_list_node_init(void *, uu_list_node_t *, \
		    uu_list_pool_t *);
version		SUNWprivate_1.1
end

function	uu_list_node_fini
include		<libuutil.h>
declaration	void uu_list_node_fini(void *, uu_list_node_t *, \
		    uu_list_pool_t *);
version		SUNWprivate_1.1
end

function	uu_list_create
include		<libuutil.h>
declaration	uu_list_t *uu_list_create(uu_list_pool_t *, void *, uint32_t);
version		SUNWprivate_1.1
end

function	uu_list_destroy
include		<libuutil.h>
declaration	void uu_list_destroy(uu_list_t *);
version		SUNWprivate_1.1
end

function	uu_list_insert
include		<libuutil.h>
declaration	void uu_list_insert(uu_list_t *, void *, uu_list_index_t);
version		SUNWprivate_1.1
end

function	uu_list_find
include		<libuutil.h>
declaration	void *uu_list_find(uu_list_t *, void *, \
		    void *, uu_list_index_t *);
version		SUNWprivate_1.1
end

function	uu_list_nearest_next
include		<libuutil.h>
declaration	void *uu_list_nearest_next(uu_list_t *, uu_list_index_t);
version		SUNWprivate_1.1
end

function	uu_list_nearest_prev
include		<libuutil.h>
declaration	void *uu_list_nearest_prev(uu_list_t *, uu_list_index_t);
version		SUNWprivate_1.1
end

function	uu_list_remove
include		<libuutil.h>
declaration	void uu_list_remove(uu_list_t *, void *);
version		SUNWprivate_1.1
end

function	uu_list_walk
include		<libuutil.h>
declaration	int uu_list_walk(uu_list_t *, uu_walk_fn_t *, void *, uint32_t);
version		SUNWprivate_1.1
end

function	uu_list_walk_start
include		<libuutil.h>
declaration	uu_list_walk_t *uu_list_walk_start(uu_list_t *, uint32_t);
version		SUNWprivate_1.1
end

function	uu_list_walk_next
include		<libuutil.h>
declaration	void *uu_list_walk_next(uu_list_walk_t *);
version		SUNWprivate_1.1
end

function	uu_list_walk_end
include		<libuutil.h>
declaration	void uu_list_walk_end(uu_list_walk_t *);
version		SUNWprivate_1.1
end

function	uu_list_numnodes
include		<libuutil.h>
declaration	size_t uu_list_numnodes(uu_list_t *);
version		SUNWprivate_1.1
end

function	uu_list_first
include		<libuutil.h>
declaration	void *uu_list_first(uu_list_t *);
version		SUNWprivate_1.1
end

function	uu_list_last
include		<libuutil.h>
declaration	void *uu_list_last(uu_list_t *);
version		SUNWprivate_1.1
end

function	uu_list_next
include		<libuutil.h>
declaration	void *uu_list_next(uu_list_t *, void *);
version		SUNWprivate_1.1
end

function	uu_list_prev
include		<libuutil.h>
declaration	void *uu_list_prev(uu_list_t *, void *);
version		SUNWprivate_1.1
end

function	uu_list_teardown
include		<libuutil.h>
declaration	void *uu_list_teardown(uu_list_t *, void **);
version		SUNWprivate_1.1
end

function	uu_list_insert_before
include		<libuutil.h>
declaration	int uu_list_insert_before(uu_list_t *, void *, void *);
version		SUNWprivate_1.1
end

function	uu_list_insert_after
include		<libuutil.h>
declaration	int uu_list_insert_after(uu_list_t *, void *, void *);
version		SUNWprivate_1.1
end

#
# avl functions
#

function	uu_avl_pool_create
include		<libuutil.h>
declaration	uu_avl_pool_t *uu_avl_pool_create(const char *, \
		    size_t, size_t, uu_compare_fn_t, uint32_t);
version		SUNWprivate_1.1
end

function	uu_avl_pool_destroy
include		<libuutil.h>
declaration	void uu_avl_pool_destroy(uu_avl_pool_t *);
version		SUNWprivate_1.1
end

function	uu_avl_node_init
include		<libuutil.h>
declaration	void uu_avl_node_init(void *, uu_avl_node_t *, uu_avl_pool_t *);
version		SUNWprivate_1.1
end

function	uu_avl_node_fini
include		<libuutil.h>
declaration	void uu_avl_node_fini(void *, uu_avl_node_t *, uu_avl_pool_t *);
version		SUNWprivate_1.1
end

function	uu_avl_create
include		<libuutil.h>
declaration	uu_avl_t *uu_avl_create(uu_avl_pool_t *, void *, uint32_t);
version		SUNWprivate_1.1
end

function	uu_avl_destroy
include		<libuutil.h>
declaration	void uu_avl_destroy(uu_avl_t *);
version		SUNWprivate_1.1
end

function	uu_avl_insert
include		<libuutil.h>
declaration	void uu_avl_insert(uu_avl_t *, void *, uu_avl_index_t);
version		SUNWprivate_1.1
end

function	uu_avl_find
include		<libuutil.h>
declaration	void *uu_avl_find(uu_avl_t *, void *, \
		    void *, uu_avl_index_t *);
version		SUNWprivate_1.1
end

function	uu_avl_nearest_next
include		<libuutil.h>
declaration	void *uu_avl_nearest_next(uu_avl_t *, uu_avl_index_t);
version		SUNWprivate_1.1
end

function	uu_avl_nearest_prev
include		<libuutil.h>
declaration	void *uu_avl_nearest_prev(uu_avl_t *, uu_avl_index_t);
version		SUNWprivate_1.1
end

function	uu_avl_remove
include		<libuutil.h>
declaration	void uu_avl_remove(uu_avl_t *, void *);
version		SUNWprivate_1.1
end

function	uu_avl_walk
include		<libuutil.h>
declaration	int uu_avl_walk(uu_avl_t *, uu_walk_fn_t *, void *, uint32_t);
version		SUNWprivate_1.1
end

function	uu_avl_walk_start
include		<libuutil.h>
declaration	uu_avl_walk_t *uu_avl_walk_start(uu_avl_t *, uint32_t);
version		SUNWprivate_1.1
end

function	uu_avl_walk_next
include		<libuutil.h>
declaration	void *uu_avl_walk_next(uu_avl_walk_t *);
version		SUNWprivate_1.1
end

function	uu_avl_walk_end
include		<libuutil.h>
declaration	void uu_avl_walk_end(uu_avl_walk_t *);
version		SUNWprivate_1.1
end

function	uu_avl_numnodes
include		<libuutil.h>
declaration	size_t uu_avl_numnodes(uu_avl_t *);
version		SUNWprivate_1.1
end

function	uu_avl_first
include		<libuutil.h>
declaration	void *uu_avl_first(uu_avl_t *);
version		SUNWprivate_1.1
end

function	uu_avl_last
include		<libuutil.h>
declaration	void *uu_avl_last(uu_avl_t *);
version		SUNWprivate_1.1
end

function	uu_avl_next
include		<libuutil.h>
declaration	void *uu_avl_next(uu_avl_t *, void *);
version		SUNWprivate_1.1
end

function	uu_avl_prev
include		<libuutil.h>
declaration	void *uu_avl_prev(uu_avl_t *, void *);
version		SUNWprivate_1.1
end

function	uu_avl_teardown
include		<libuutil.h>
declaration	void *uu_avl_teardown(uu_avl_t *, void **);
version		SUNWprivate_1.1
end
