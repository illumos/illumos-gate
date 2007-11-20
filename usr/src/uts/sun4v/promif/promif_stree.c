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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>
#include <sys/kmem.h>
#include <sys/machsystm.h>

/*
 * A property attached to a node in the kernel's
 * shadow copy of the PROM device tree.
 */
typedef struct prom_prop {
	struct prom_prop *pp_next;
	char		 *pp_name;
	int		 pp_len;
	void		 *pp_val;
} prom_prop_t;

/*
 * A node in the kernel's shadow copy of the PROM
 * device tree.
 */
typedef struct prom_node {
	pnode_t			pn_nodeid;
	struct prom_prop	*pn_propp;
	struct prom_node	*pn_parent;
	struct prom_node	*pn_child;
	struct prom_node	*pn_sibling;
} prom_node_t;

static prom_node_t *promif_root;

static prom_node_t *find_node(pnode_t nodeid);
static prom_node_t *find_node_work(prom_node_t *np, pnode_t node);
static int getproplen(prom_node_t *pnp, char *name);
static void *getprop(prom_node_t *pnp, char *name);
static char *nextprop(prom_node_t *pnp, char *name);

#ifndef _KMDB
static void create_prop(prom_node_t *pnp, char *name, void *val, int len);
static prom_node_t *create_node(prom_node_t *parent, pnode_t node);
static void create_peers(prom_node_t *pnp, pnode_t node);
static void create_children(prom_node_t *pnp, pnode_t parent);
#endif

/*
 * Hooks for kmdb for accessing the PROM shadow tree. The driver portion
 * of kmdb will retrieve the root of the tree and pass it down to the
 * debugger portion of kmdb. As the kmdb debugger is standalone, it has
 * its own promif_root pointer that it will be set to the value passed by
 * the driver so that kmdb points to the shadow tree maintained by the kernel.
 * So the "get" function is in the kernel while the "set" function is in kmdb.
 */
#ifdef _KMDB
void
promif_stree_setroot(void *root)
{
	promif_root = (prom_node_t *)root;
}
#else
void *
promif_stree_getroot(void)
{
	return (promif_root);
}
#endif

/*
 * Interfaces used internally by promif functions.
 * These hide all accesses to the shadow tree.
 */

pnode_t
promif_stree_parentnode(pnode_t nodeid)
{
	prom_node_t *pnp;

	pnp = find_node(nodeid);
	if (pnp && pnp->pn_parent) {
		return (pnp->pn_parent->pn_nodeid);
	}

	return (OBP_NONODE);
}

pnode_t
promif_stree_childnode(pnode_t nodeid)
{
	prom_node_t *pnp;

	pnp = find_node(nodeid);
	if (pnp && pnp->pn_child)
		return (pnp->pn_child->pn_nodeid);

	return (OBP_NONODE);
}

pnode_t
promif_stree_nextnode(pnode_t nodeid)
{
	prom_node_t *pnp;

	/*
	 * Note: next(0) returns the root node
	 */
	pnp = find_node(nodeid);
	if (pnp && (nodeid == OBP_NONODE))
		return (pnp->pn_nodeid);
	if (pnp && pnp->pn_sibling)
		return (pnp->pn_sibling->pn_nodeid);

	return (OBP_NONODE);
}

int
promif_stree_getproplen(pnode_t nodeid, char *name)
{
	prom_node_t *pnp;

	pnp = find_node(nodeid);
	if (pnp == NULL)
		return (-1);

	return (getproplen(pnp, name));
}

int
promif_stree_getprop(pnode_t nodeid, char *name, void *value)
{
	prom_node_t	*pnp;
	void		*prop;
	int		len;

	pnp = find_node(nodeid);
	if (pnp == NULL) {
		prom_printf("find_node: no node?\n");
		return (-1);
	}

	len = getproplen(pnp, name);
	if (len > 0) {
		prop = getprop(pnp, name);
		bcopy(prop, value, len);
	} else {
		prom_printf("find_node: getproplen: %d\n", len);
	}

	return (len);
}

char *
promif_stree_nextprop(pnode_t nodeid, char *name, char *next)
{
	prom_node_t	*pnp;
	char		*propname;

	next[0] = '\0';

	pnp = find_node(nodeid);
	if (pnp == NULL)
		return (NULL);

	propname = nextprop(pnp, name);
	if (propname == NULL)
		return (next);

	(void) prom_strcpy(next, propname);

	return (next);
}

static prom_node_t *
find_node_work(prom_node_t *np, pnode_t node)
{
	prom_node_t *nnp;
	prom_node_t *snp;

	for (snp = np; snp != NULL; snp = snp->pn_sibling) {
		if (snp->pn_nodeid == node)
			return (snp);

		if (snp->pn_child)
			if ((nnp = find_node_work(snp->pn_child, node)) != NULL)
				return (nnp);
	}

	return (NULL);
}

static prom_node_t *
find_node(pnode_t nodeid)
{

	if (nodeid == OBP_NONODE)
		return (promif_root);

	if (promif_root == NULL)
		return (NULL);

	return (find_node_work(promif_root, nodeid));
}

static int
getproplen(prom_node_t *pnp, char *name)
{
	struct prom_prop *propp;

	for (propp = pnp->pn_propp; propp != NULL; propp = propp->pp_next)
		if (prom_strcmp(propp->pp_name, name) == 0)
			return (propp->pp_len);

	return (-1);
}

static void *
getprop(prom_node_t *np, char *name)
{
	struct prom_prop *propp;

	for (propp = np->pn_propp; propp != NULL; propp = propp->pp_next)
		if (prom_strcmp(propp->pp_name, name) == 0)
			return (propp->pp_val);

	return (NULL);
}

static char *
nextprop(prom_node_t *pnp, char *name)
{
	struct prom_prop *propp;

	/*
	 * getting next of NULL or a null string returns the first prop name
	 */
	if (name == NULL || *name == '\0')
		if (pnp->pn_propp)
			return (pnp->pn_propp->pp_name);

	for (propp = pnp->pn_propp; propp != NULL; propp = propp->pp_next)
		if (prom_strcmp(propp->pp_name, name) == 0)
			if (propp->pp_next)
				return (propp->pp_next->pp_name);

	return (NULL);
}

#ifndef _KMDB

int
promif_stree_setprop(pnode_t nodeid, char *name, void *value, int len)
{
	prom_node_t		*pnp;
	struct prom_prop	*prop;

	pnp = find_node(nodeid);
	if (pnp == NULL) {
		prom_printf("find_node: no node?\n");
		return (-1);
	}

	/*
	 * If a property with this name exists, replace the existing
	 * value.
	 */
	for (prop = pnp->pn_propp; prop; prop = prop->pp_next)
		if (prom_strcmp(prop->pp_name, name) == 0) {
			kmem_free(prop->pp_val, prop->pp_len);
			prop->pp_val = NULL;
			if (len > 0) {
				/*
				 * Make sure we don't get dispatched onto a
				 * different cpu if we happen to sleep.  See
				 * kern_postprom().
				 */
				thread_affinity_set(curthread, CPU_CURRENT);
				prop->pp_val = kmem_zalloc(len, KM_SLEEP);
				thread_affinity_clear(curthread);

				bcopy(value, prop->pp_val, len);
			}
			prop->pp_len = len;
			return (len);
		}

	return (-1);
}

/*
 * Create a promif private copy of boot's device tree.
 */
void
promif_stree_init(void)
{
	pnode_t		node;
	prom_node_t	*pnp;

	node = prom_rootnode();
	promif_root = pnp = create_node(OBP_NONODE, node);

	create_peers(pnp, node);
	create_children(pnp, node);
}

static void
create_children(prom_node_t *pnp, pnode_t parent)
{
	prom_node_t	*cnp;
	pnode_t		child;

	_NOTE(CONSTCOND)
	while (1) {
		child = prom_childnode(parent);
		if (child == 0)
			break;
		if (prom_getproplen(child, "name") <= 0) {
			parent = child;
			continue;
		}
		cnp = create_node(pnp, child);
		pnp->pn_child = cnp;
		create_peers(cnp, child);
		pnp = cnp;
		parent = child;
	}
}

static void
create_peers(prom_node_t *np, pnode_t node)
{
	prom_node_t	*pnp;
	pnode_t		peer;

	_NOTE(CONSTCOND)
	while (1) {
		peer = prom_nextnode(node);
		if (peer == 0)
			break;
		if (prom_getproplen(peer, "name") <= 0) {
			node = peer;
			continue;
		}
		pnp = create_node(np->pn_parent, peer);
		np->pn_sibling = pnp;
		create_children(pnp, peer);
		np = pnp;
		node = peer;
	}
}

static prom_node_t *
create_node(prom_node_t *parent, pnode_t node)
{
	prom_node_t	*pnp;
	char		prvname[OBP_MAXPROPNAME];
	char		propname[OBP_MAXPROPNAME];
	int		proplen;
	void		*propval;

	/*
	 * Make sure we don't get dispatched onto a different
	 * cpu if we happen to sleep.  See kern_postprom().
	 */
	thread_affinity_set(curthread, CPU_CURRENT);

	pnp = kmem_zalloc(sizeof (prom_node_t), KM_SLEEP);
	pnp->pn_nodeid = node;
	pnp->pn_parent = parent;

	prvname[0] = '\0';

	_NOTE(CONSTCOND)
	while (1) {
		(void) prom_nextprop(node, prvname, propname);
		if (prom_strlen(propname) == 0)
			break;
		if ((proplen = prom_getproplen(node, propname)) == -1)
			continue;
		propval = NULL;
		if (proplen != 0) {
			propval = kmem_zalloc(proplen, KM_SLEEP);
			(void) prom_getprop(node, propname, propval);
		}
		create_prop(pnp, propname, propval, proplen);

		(void) prom_strcpy(prvname, propname);
	}

	thread_affinity_clear(curthread);

	return (pnp);
}

static void
create_prop(prom_node_t *pnp, char *name, void *val, int len)
{
	struct prom_prop	*prop;
	struct prom_prop	*newprop;

	/*
	 * Make sure we don't get dispatched onto a different
	 * cpu if we happen to sleep.  See kern_postprom().
	 */
	thread_affinity_set(curthread, CPU_CURRENT);
	newprop = kmem_zalloc(sizeof (*newprop), KM_SLEEP);
	newprop->pp_name = kmem_zalloc(prom_strlen(name) + 1, KM_SLEEP);
	thread_affinity_clear(curthread);

	(void) prom_strcpy(newprop->pp_name, name);
	newprop->pp_val = val;
	newprop->pp_len = len;

	if (pnp->pn_propp == NULL) {
		pnp->pn_propp = newprop;
		return;
	}

	/* move to the end of the prop list */
	for (prop = pnp->pn_propp; prop->pp_next != NULL; prop = prop->pp_next)
		/* empty */;

	/* append the new prop */
	prop->pp_next = newprop;
}

static void
promif_dump_tree(prom_node_t *pnp)
{
	int		i;
	static int	level = 0;

	if (pnp == NULL)
		return;

	for (i = 0; i < level; i++) {
		prom_printf("    ");
	}

	prom_printf("Node 0x%x (parent=0x%x, sibling=0x%x)\n", pnp->pn_nodeid,
	    (pnp->pn_parent) ? pnp->pn_parent->pn_nodeid : 0,
	    (pnp->pn_sibling) ? pnp->pn_sibling->pn_nodeid : 0);

	if (pnp->pn_child != NULL) {
		level++;
		promif_dump_tree(pnp->pn_child);
		level--;
	}

	if (pnp->pn_sibling != NULL)
		promif_dump_tree(pnp->pn_sibling);
}

#endif
