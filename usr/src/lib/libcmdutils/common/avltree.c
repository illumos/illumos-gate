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
 *
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/avl.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include "libcmdutils.h"

/*
 * The following interfaces complement the interfaces available in
 * libavl.
 * 	tnode_compare() - tree node comparison routine
 *	add_tnode() - adds nodes to a tree
 *	destroy_tree() - destroys a whole tree
 *
 * The libavl routines are very generic and don't have any
 * direct knowledge about the data being stored in the AVL tree,
 * nor any of the details of the AVL tree representation.
 * In addition, the libavl routines do not perform any locking
 * or memory allocation.  Appropriate synchronization and memory
 * allocation are the responsibility of the user of the libavl
 * routines.
 *
 * These routines, and the structures defined in "libcmdutils.h",
 * provide the necessary details about the data and AVL tree
 * representation.  Currently, the routines available in
 * libcmdutils perform necessary memory allocations, and do not
 * perform locking, therefore they are not thread safe and
 * should not be used by multi-threaded applications.
 *
 * For more information on the avl tree routines, see the well
 * documented source code in avl.c, and the header files in
 * <sys/avl.h> and <sys/avl_impl.h>.
 *
 * Note: The tree must be initialized in the calling application
 * before calling these routines. An example of how this is done:
 *	static avl_tree_t       *tree = NULL;
 *
 * tnode_compare() - This function is used by libavl's avl_find()
 * routine to abstract out how the data structures are ordered, and
 * must be an argument to libavl's avl_create() function.  Therefore,
 * this routine should not be called directly from the calling
 * application.
 *
 * Input:
 *	const void *p1	(pointer to the 1st node to compare and
 *			 is the node which we are try to match
 *			 or insert into the search tree)
 *	const void *p2	(pointer to the 2nd node to compare and
 *			 is a node which already exists in the
 *			 search tree)
 *
 * This function returns (as required by the libavl interfaces):
 * 	* -1 if the 1st argument node is less than the 2nd
 * 	* 0 if the nodes are equal in value
 * 	* +1 if the 1st node is greater than the 2nd
 *
 * add_tnode() - Builds a height balanced tree of nodes consisting of
 * a device id and inode number provided by the calling application.
 * The nodes are stored in the specified search tree by using the
 * tnode_compare() routine. Duplicate nodes are not stored.
 *
 * If the specified search tree does not exist (is NULL), then memory
 * is allocated for the tree, and libavl's avl_create() routine is
 * called to initialize the tree with the comparison routine
 * (tnode_compare()) which will be used to compare the tree nodes
 * and populate the tree on subsequent calls by add_tnode() to
 * avl_find().
 *
 * This routine creates a node to be added to the search tree by
 * allocating memory and setting the nodes device id and inode number
 * to those specified.  If the node does not exist in the search tree,
 * it is added.  If the node already exists in the tree, it is not
 * added (remember, duplicate nodes are not stored), and the node is
 * freed.
 *
 * Input:
 *	avl_tree_t **stree 	(search tree the data is to be stored in)
 *	dev_t device		(device id of the inode to be stored)
 *	ino_t inode		(inode number of inode to be stored)
 *
 * This function returns:
 * 	* +1 if the node was added
 * 	* 0 if the node was not added (node already exists)
 * 	* -1 if an error occurred (memory allocation problem)
 *
 * destroy_tree() - The specified tree is destroyed by calling
 * libavl's avl_destroy_nodes() routine to delete a tree without
 * any rebalancing.  Memory is freed that had been previously allocated
 * by add_tnode() for the tree's nodes and the search tree itself.
 *
 * Input:
 *	avl_tree_t *stree	(search tree to destroy)
 *
 * This function does not return anything.  Note:  The calling
 * application is responsible for setting the search tree to NULL upon
 * return.
 */

/*
 * Compare two nodes by first trying to match on the node's device
 * id, then on the inode number.  Return -1 when p1 < p2,
 * 0 when p1 == p2, and 1 when p1 > p2.  This function is invoked
 * by avl_find.  p1 is always the node we are trying to insert or
 * match in the search database.
 */
int
tnode_compare(const void *p1, const void *p2)
{
	tree_node_t *n1 = (tree_node_t *)p1;
	tree_node_t *n2 = (tree_node_t *)p2;

	/* first match device id */
	if (n1->node_dev < n2->node_dev) {
		return (-1);
	} else if (n1->node_dev == n2->node_dev) {
		/* device id match, now check inode */
		if (n1->node_ino < n2->node_ino) {
			return (-1);
		} else if (n1->node_ino == n2->node_ino) {
			return (0);
		} else {
			return (1);
		}
	} else {
		return (1);
	}
}

/*
 * Build a height balanced tree of nodes consisting of a device id and
 * an inode number.  Duplicate nodes are not stored.  Return 1 if
 * node was added to the tree, return -1 upon error, otherwise return 0.
 */
int
add_tnode(avl_tree_t **stree, dev_t device, ino_t inode)
{
	tree_node_t	*tnode;
	avl_index_t	where;

	/*
	 * Create an AVL search tree to keep track of inodes
	 * visited/reported.
	 */
	if (*stree == NULL) {
		if ((*stree = calloc(1, sizeof (avl_tree_t)))
		    == NULL) {
			return (-1);
		}
		avl_create(*stree,
		    tnode_compare,
		    sizeof (tree_node_t),
		    offsetof(tree_node_t, avl_link));
	}

	/* Initialize the node */
	if ((tnode = calloc(1, sizeof (*tnode))) == NULL) {
		return (-1);
	}
	tnode->node_dev = device;
	tnode->node_ino = inode;

	/* If the node is not already in the tree, then insert it */
	if (avl_find(*stree, tnode, &where) == NULL) {
		avl_insert(*stree, tnode, where);
		return (1);
	}

	/* The node is already in the tree, so just free it */
	free(tnode);
	return (0);
}

/*
 * Destroy a search tree.
 */
void
destroy_tree(avl_tree_t *stree)
{
	void *cookie;
	tree_node_t	*tnode;

	if (stree != NULL) {

		cookie = NULL;
		while ((tnode = avl_destroy_nodes(stree, &cookie)) != NULL) {
			free(tnode);
		}
		avl_destroy(stree);
		free(stree);
	}
}
