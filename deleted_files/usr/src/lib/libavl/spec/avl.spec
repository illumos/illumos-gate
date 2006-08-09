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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libavl/spec/avl.spec

function	avl_create
include		<sys/avl.h>
declaration	void avl_create(avl_tree_t *tree,
		int (*compar)(const void *, const void *), size_t size,
		size_t offset)
version		SUNWprivate_1.1
end

function	avl_destroy
include		<sys/avl.h>
declaration	void avl_destroy(avl_tree_t *tree)
version		SUNWprivate_1.1
end

function	avl_destroy_nodes
include		<sys/avl.h>
declaration	void *avl_destroy_nodes(avl_tree_t *tree, void **cookie)
version		SUNWprivate_1.1
end

function	avl_find
include		<sys/avl.h>
declaration	void *avl_find(avl_tree_t  *tree, void *value,
		avl_index_t *where)
version		SUNWprivate_1.1
end

function	avl_first
include		<sys/avl.h>
declaration	void *avl_first(avl_tree_t *tree)
version		SUNWprivate_1.1
end

function	avl_insert
include		<sys/avl.h>
declaration	void avl_insert(avl_tree_t  *tree, void *new_data,
		avl_index_t where)
version		SUNWprivate_1.1
end

function	avl_insert_here
include		<sys/avl.h>
declaration	void avl_insert(avl_tree_t  *tree, void *new_data, void *here,
		int direction)
version		SUNWprivate_1.1
end

function	avl_last
include		<sys/avl.h>
declaration	void *avl_last(avl_tree_t *tree)
version		SUNWprivate_1.1
end

function	avl_nearest
include		<sys/avl.h>
declaration	void *avl_nearest(avl_tree_t *tree, avl_index_t where,
		int direction)
version		SUNWprivate_1.1
end

function	avl_numnodes
include		<sys/avl.h>
declaration	ulong_t avl_numnodes(avl_tree_t *tree)
version		SUNWprivate_1.1
end

function	avl_add
include		<sys/avl.h>
declaration	void avl_remove(avl_tree_t *tree, void *data)
version		SUNWprivate_1.1
end

function	avl_remove
include		<sys/avl.h>
declaration	void avl_remove(avl_tree_t *tree, void *data)
version		SUNWprivate_1.1
end

function	avl_walk
include		<sys/avl.h>
declaration	void *avl_walk(avl_tree_t *tree, void *oldnode, int left)
version		SUNWprivate_1.1
end
