/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Declarations for the functions in libcmdutils.
 */

#ifndef	_LIBCMDUTILS_H
#define	_LIBCMDUTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This is a private header file.  Applications should not directly include
 * this file.
 */

#include <sys/avl.h>
#include <sys/types.h>
#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* avltree */
#define	OFFSETOF(s, m)	((size_t)(&(((s *)0)->m)))

/* Type used for a node containing a device id and inode number */
typedef struct tree_node {
	dev_t		node_dev;
	ino_t		node_ino;
	avl_node_t	avl_link;
} tree_node_t;

/*
 * Used to compare two nodes.  We are attempting to match the 1st
 * argument (node) against the 2nd argument (a node which
 * is already in the search tree).
 */
extern int tnode_compare(const void *, const void *);

/*
 * Used to add a single node (containing the input device id and
 * inode number) to the specified search tree.  The calling
 * application must set the tree pointer to NULL before calling
 * add_tnode() for the first time.
 */
extern int add_tnode(avl_tree_t **, dev_t, ino_t);

/*
 * Used to destroy a whole tree (all nodes) without rebalancing.
 * The calling application is responsible for setting the tree
 * pointer to NULL upon return.
 */
extern void destroy_tree(avl_tree_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBCMDUTILS_H */
