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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PROM_EMUL_H
#define	_SYS_PROM_EMUL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following structure describes a property attached to a node
 * in the in-kernel copy of the PROM device tree.
 */
struct prom_prop {
	struct prom_prop *pp_next;
	char		 *pp_name;
	int		 pp_len;
	void		 *pp_val;
};

/*
 * The following structure describes a node in the in-kernel copy
 * of the PROM device tree.
 */
struct prom_node {
	pnode_t	pn_nodeid;
	struct prom_prop *pn_propp;
	struct prom_node *pn_child;
	struct prom_node *pn_sibling;
};

typedef struct prom_node prom_node_t;

/*
 * These are promif emulation functions, intended only for promif use
 */
extern void promif_create_device_tree(void);

extern pnode_t promif_findnode_byname(pnode_t n, char *name);
extern pnode_t promif_nextnode(pnode_t n);
extern pnode_t promif_childnode(pnode_t n);

extern int promif_getproplen(pnode_t n, char *name);
extern int promif_getprop(pnode_t n,  char *name, void *value);
extern int promif_bounded_getprop(pnode_t, char *name, void *value, int len);
char *promif_nextprop(pnode_t n, char *previous, char *next);

/*
 * XXX: The following functions are unsafe and unecessary, and should be
 * XXX: removed. OS created nodes belong in the OS copy of the device tree.
 * XXX: The OS should not be creating nodes in the prom's device tree!
 */
extern pnode_t promif_add_child(pnode_t parent, pnode_t child, char *name);
extern void promif_create_prop_external(pnode_t, char *name, void *, int);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROM_EMUL_H */
