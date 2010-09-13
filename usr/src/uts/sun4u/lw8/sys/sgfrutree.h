/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SGFRUTREE_H
#define	_SGFRUTREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/sgfru.h>

#define	ROOTPARENT		0		/* well-known node value */
#define	MAX_NODE_CHILDREN	16		/* hint */
#define	MAX_NODE_NAME		16		/* max name size */

/*
 * PICL classes used by serengeti sgfrutree
 */
#define	TEMP_CLASS		0x0		/* currently unused */
#define	FRU_CLASS		0x1		/* fru class */
#define	LOCATION_CLASS		0x2		/* location class */
#define	PSEUDO_FRU_CLASS	0x3		/* fru class with no seeprom */

typedef struct {
	fru_hdl_t	handle;			/* (container) handle */
	char		nodename[MAX_NODE_NAME]; /* picl nodename, thing name */
	int16_t		has_children;		/* hint if node has children */
	uint16_t	class;			/* one of the picl classes */
	union class_info {
	    struct location_info {
		int16_t	slot;			/* location: valid slot or -1 */
		char	label[MAX_NODE_NAME];	/* label property, place name */
	    } linfo;
	} cinfo;
} node_t;

#define	location_slot	cinfo.linfo.slot
#define	location_label	cinfo.linfo.label

typedef frup_info_t	child_info_t;
typedef frup_info_t	handles_t;
typedef frup_info_t	node_info_t;

/*
 *   PICL FRU Hierarchy
 *
 *	    + frutree
 *	    |
 *	    +-- safari-node
 *		|
 *		+-- picl fru node, name = <name> (picl class = fru)
 *		|
 *		+-- picl location node, name = <name> (picl class = location)
 *		|     o optional property slot = <instance>
 *		|
 *		+-- picl location node, name = <name> (picl class = location)
 *		|  |  o optional property slot = <instance>
 *		|  |
 *		|  +-- picl fru node, name = <name> (picl class = fru)
 *		|
 *		+-- picl tree sibling +-- picl tree child
 *
 *
 * Request: child_info_t, with parent fru handle and max count
 * Receive: child_info_t, with child_info_t array and actual count
 */
#define	SGFRU_GETCHILDLIST			0x000f
/*
 * Request: handles_t, with fru handle, max count, and preallocated buffer
 * Receive: handles_t, with handle array and actual count
 */
#define	SGFRU_GETCHILDHANDLES			0x0010
/*
 * Request: node_info_t, with fru handle
 * Receive: node_info_t, with node_t info for the node
 */
#define	SGFRU_GETNODEINFO			0x0020

#ifdef DEBUG
/*
 * DESCRIPTION
 *   fru_get_children() fills an array of structures representing the
 *   children of a node.
 *
 * ARGUMENTS
 *
 * RETURN
 *   int
 *     On success, the number of node_t structures written is returned;
 *     on error, -1 is returned and "errno" is set appropriately.
 *
 * ERRORS
 *   ENOMEM
 *     The parent FRU has more than "max_children" children.
 */
int fru_get_children(fru_hdl_t parent, node_t *children, int max_children);

/*
 * DESCRIPTION
 *   fru_get_handles() fills an array of structures representing the
 *   children of a node that have FRUs. Use 0 for the top root node.
 *
 * ARGUMENTS
 *
 * RETURN
 *   int
 *     On success, the number of fru_hdl_t structures written is returned;
 *     on error, -1 is returned and "errno" is set appropriately.
 *
 * ERRORS
 *   ENOMEM
 *     The parent FRU has more than "max_handles" children.
 */
int fru_get_handles(fru_hdl_t parent, fru_hdl_t *children, int max_handles);

/*
 * DESCRIPTION
 *   fru_get_node_info() gets the node_t info for a handle.
 *
 * ARGUMENTS
 *
 * RETURN
 *   int
 *     On success, 0 is returned as well as the node_info;
 *     on error, -1 is returned and "errno" is set appropriately.
 *
 * ERRORS
 */
int fru_get_node_info(fru_hdl_t node_hdl, node_t *node);
#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SGFRUTREE_H */
