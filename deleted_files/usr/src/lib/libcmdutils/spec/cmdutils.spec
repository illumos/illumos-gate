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
# lib/libcmdutils/spec/cmdutils.spec

function	tnode_compare
include		<sys/avl.h>
declaration	int tnode_compare(const void *, const void *);
version		SUNWprivate_1.1
end		

function	destroy_tree
include		<sys/avl.h>
declaration	void destroy_tree(avl_tree_t *);
version		SUNWprivate_1.1
end		

function	add_tnode
include		<sys/avl.h>
declaration	int add_tnode(avl_tree_t **, dev_t, ino_t);
version		SUNWprivate_1.1
end		
