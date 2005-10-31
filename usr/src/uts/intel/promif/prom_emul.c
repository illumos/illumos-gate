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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/prom_emul.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>

static prom_node_t *promif_top;

static prom_node_t *promif_find_node(pnode_t nodeid);
static int getproplen(prom_node_t *pnp, char *name);
static void *getprop(prom_node_t *pnp, char *name);

static void
promif_create_prop(prom_node_t *pnp, char *name, void *val, int len, int flags)
{
	struct prom_prop *p, *q;

	q = kmem_zalloc(sizeof (*q), KM_SLEEP);
	q->pp_name = kmem_zalloc(strlen(name) + 1, KM_SLEEP);
	(void) strcpy(q->pp_name, name);
	q->pp_val = kmem_alloc(len, KM_SLEEP);
	q->pp_len = len;
	switch (flags) {
	case DDI_PROP_TYPE_INT:
	case DDI_PROP_TYPE_INT64:
		/*
		 * Technically, we need byte-swapping to conform to 1275.
		 * However, the old x86 prom simulator used little endian
		 * representation, so we don't swap here either.
		 *
		 * NOTE: this is inconsistent with ddi_prop_lookup_*()
		 * which does byte-swapping when looking up prom properties.
		 * Since all kernel nodes are SID nodes, drivers no longer
		 * access PROM properties on x86.
		 */
	default:	/* no byte swapping */
		(void) bcopy(val, q->pp_val, len);
		break;
	}

	if (pnp->pn_propp == NULL) {
		pnp->pn_propp = q;
		return;
	}

	for (p = pnp->pn_propp; p->pp_next != NULL; p = p->pp_next)
		/* empty */;

	p->pp_next = q;
}

static prom_node_t *
promif_create_node(dev_info_t *dip)
{
	prom_node_t *pnp;
	ddi_prop_t *hwprop;
	char *nodename;

	pnp = kmem_zalloc(sizeof (prom_node_t), KM_SLEEP);
	pnp->pn_nodeid = DEVI(dip)->devi_nodeid;

	hwprop = DEVI(dip)->devi_hw_prop_ptr;
	while (hwprop != NULL) {
		/* need to encode to proper endianness */
		promif_create_prop(pnp, hwprop->prop_name, hwprop->prop_val,
		    hwprop->prop_len, hwprop->prop_flags & DDI_PROP_TYPE_MASK);
		hwprop = hwprop->prop_next;
	}
	nodename = ddi_node_name(dip);
	promif_create_prop(pnp, "name", nodename, strlen(nodename) + 1,
	    DDI_PROP_TYPE_STRING);

	return (pnp);
}

static void promif_create_children(prom_node_t *, dev_info_t *);

static void
promif_create_peers(prom_node_t *pnp, dev_info_t *dip)
{
	dev_info_t *ndip = ddi_get_next_sibling(dip);

	while (ndip) {
		pnp->pn_sibling = promif_create_node(ndip);
		promif_create_children(pnp->pn_sibling, ndip);
		pnp = pnp->pn_sibling;
		ndip = ddi_get_next_sibling(ndip);
	}
}

static void
promif_create_children(prom_node_t *pnp, dev_info_t *dip)
{
	dev_info_t *cdip = ddi_get_child(dip);

	while (cdip) {
		pnp->pn_child = promif_create_node(cdip);
		promif_create_peers(pnp->pn_child, cdip);
		pnp = pnp->pn_child;
		cdip = ddi_get_child(cdip);
	}
}

void
promif_create_device_tree(void)
{
	promif_top = promif_create_node(ddi_root_node());
	promif_create_children(promif_top, ddi_root_node());
}

static prom_node_t *
find_node_work(prom_node_t *pnp, pnode_t n)
{
	prom_node_t *qnp;

	if (pnp->pn_nodeid == n)
		return (pnp);

	if (pnp->pn_child)
		if ((qnp = find_node_work(pnp->pn_child, n)) != NULL)
			return (qnp);

	if (pnp->pn_sibling)
		if ((qnp = find_node_work(pnp->pn_sibling, n)) != NULL)
			return (qnp);

	return (NULL);
}

static prom_node_t *
promif_find_node(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return (promif_top);

	if (promif_top == NULL)
		return (NULL);

	return (find_node_work(promif_top, nodeid));
}

pnode_t
promif_nextnode(pnode_t nodeid)
{
	prom_node_t *pnp;

	/*
	 * Note: next(0) returns the root node
	 */
	pnp = promif_find_node(nodeid);
	if (pnp && (nodeid == OBP_NONODE))
		return (pnp->pn_nodeid);
	if (pnp && pnp->pn_sibling)
		return (pnp->pn_sibling->pn_nodeid);

	return (OBP_NONODE);
}

pnode_t
promif_childnode(pnode_t nodeid)
{
	prom_node_t *pnp;

	pnp = promif_find_node(nodeid);
	if (pnp && pnp->pn_child)
		return (pnp->pn_child->pn_nodeid);

	return (OBP_NONODE);
}

/*
 * Retrieve a PROM property (len and value)
 */

static int
getproplen(prom_node_t *pnp, char *name)
{
	struct prom_prop *propp;

	for (propp = pnp->pn_propp; propp != NULL; propp = propp->pp_next)
		if (strcmp(propp->pp_name, name) == 0)
			return (propp->pp_len);

	return (-1);
}

int
promif_getproplen(pnode_t nodeid, char *name)
{
	prom_node_t *pnp;

	pnp = promif_find_node(nodeid);
	if (pnp == NULL)
		return (-1);

	return (getproplen(pnp, name));
}

static void *
getprop(prom_node_t *pnp, char *name)
{
	struct prom_prop *propp;

	for (propp = pnp->pn_propp; propp != NULL; propp = propp->pp_next)
		if (strcmp(propp->pp_name, name) == 0)
			return (propp->pp_val);

	return (NULL);
}

int
promif_getprop(pnode_t nodeid, char *name, void *value)
{
	prom_node_t *pnp;
	void *v;
	int len;

	pnp = promif_find_node(nodeid);
	if (pnp == NULL)
		return (-1);

	len = getproplen(pnp, name);
	if (len > 0) {
		v = getprop(pnp, name);
		bcopy(v, value, len);
	}
	return (len);
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
		if (strcmp(propp->pp_name, name) == 0)
			if (propp->pp_next)
				return (propp->pp_next->pp_name);

	return (NULL);
}

char *
promif_nextprop(pnode_t nodeid, char *name, char *next)
{
	prom_node_t *pnp;
	char *s;

	next[0] = '\0';

	pnp = promif_find_node(nodeid);
	if (pnp == NULL)
		return (NULL);

	s = nextprop(pnp, name);
	if (s == NULL)
		return (next);

	(void) strcpy(next, s);
	return (next);
}
