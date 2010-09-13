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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/esunddi.h>
#include <sys/promif_impl.h>

#ifdef _KMDB
static pnode_t chosennode;
static pnode_t optionsnode;
#else
static char *gettoken(char *tp, char *token);
static pnode_t finddevice(char *path);
#endif

/*
 * Routines for walking the PROMs devinfo tree
 */

#ifdef _KMDB

void
promif_set_nodes(pnode_t chosen, pnode_t options)
{
	chosennode = chosen;
	optionsnode = options;
}

int
promif_finddevice(void *p)
{
	cell_t	*ci = (cell_t *)p;
	char *path;

	ASSERT(ci[1] == 1);

	path = p1275_cell2ptr(ci[3]);

	if (strcmp("/chosen", path) == 0) {
		ci[4] = p1275_dnode2cell(chosennode);
	} else if (strcmp("/options", path) == 0) {
		ci[4] = p1275_dnode2cell(optionsnode);
	} else {
		/* only supports known nodes */
		ASSERT(0);
	}

	return (0);
}

#else

int
promif_finddevice(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	node;

	ASSERT(ci[1] == 1);

	/*
	 * We are passing the cpu pointer (CPU->cpu_id) explicitly to
	 * thread_affinity_set() so that we don't attempt to grab the
	 * cpu_lock internally in thread_affinity_set() and may sleep
	 * as a result.
	 * It is safe to pass CPU->cpu_id and it will always be valid.
	 */
	thread_affinity_set(curthread, CPU->cpu_id);
	node = finddevice(p1275_cell2ptr(ci[3]));

	ci[4] = p1275_dnode2cell(node);
	thread_affinity_clear(curthread);

	return (0);
}

#endif

int
promif_nextnode(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	next;

	ASSERT(ci[1] == 1);

	next = promif_stree_nextnode(p1275_cell2dnode(ci[3]));

	ci[4] = p1275_dnode2cell(next);

	return (0);
}

int
promif_childnode(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	child;

	ASSERT(ci[1] == 1);

	child = promif_stree_childnode(p1275_cell2dnode(ci[3]));

	ci[4] = p1275_dnode2cell(child);

	return (0);
}

int
promif_parentnode(void *p)
{
	cell_t	*ci = (cell_t *)p;
	pnode_t	parent;

	ASSERT(ci[1] == 1);

	parent = promif_stree_parentnode(p1275_cell2dnode(ci[3]));

	ci[4] = p1275_dnode2cell(parent);

	return (0);
}

#ifndef _KMDB

/*
 * Get a token from a prom pathname, collecting everything
 * until a non-comma, non-colon separator is found. Any
 * options, including the ':' option separator, on the end
 * of the token are removed.
 */
static char *
gettoken(char *tp, char *token)
{
	char *result = token;

	for (;;) {
		tp = prom_path_gettoken(tp, token);
		token += prom_strlen(token);
		if ((*tp == ',') || (*tp == ':')) {
			*token++ = *tp++;
			*token = '\0';
			continue;
		}
		break;
	}

	/* strip off any options from the token */
	prom_strip_options(result, result);

	return (tp);
}

/*
 * Retrieve the unit address for a node by looking it up
 * in the corresponding dip. -1 is returned if no unit
 * address can be determined.
 */
static int
get_unit_addr(pnode_t np, char *paddr)
{
	dev_info_t	*dip;
	char		*addr;

	if ((dip = e_ddi_nodeid_to_dip(np)) == NULL) {
		return (-1);
	}

	if ((addr = ddi_get_name_addr(dip)) == NULL) {
		ddi_release_devi(dip);
		return (-1);
	}

	(void) prom_strcpy(paddr, addr);

	ddi_release_devi(dip);

	return (0);
}

/*
 * Get node id of node in prom tree that path identifies
 */
static pnode_t
finddevice(char *path)
{
	char	name[OBP_MAXPROPNAME];
	char	addr[OBP_MAXPROPNAME];
	char	pname[OBP_MAXPROPNAME];
	char	paddr[OBP_MAXPROPNAME];
	char	*tp;
	pnode_t	np;
	pnode_t	device;

	CIF_DBG_NODE("finddevice: %s\n", path);

	tp = path;
	np = prom_rootnode();
	device = OBP_BADNODE;

	/* must be a fully specified path */
	if (*tp++ != '/')
		goto done;

	for (;;) {
		/* get the name from the path */
		tp = gettoken(tp, name);
		if (*name == '\0')
			break;

		/* get the address from the path */
		if (*tp == '@') {
			tp++;
			tp = gettoken(tp, addr);
		} else {
			addr[0] = '\0';
		}

		CIF_DBG_NODE("looking for: %s%s%s\n", name,
		    (*addr != '\0') ? "@" : "", addr);

		if ((np = prom_childnode(np)) == OBP_NONODE)
			break;

		while (np != OBP_NONODE) {

			/* get the name from the current node */
			if (prom_getprop(np, OBP_NAME, pname) < 0)
				goto done;

			/* get the address from the current node */
			if (get_unit_addr(np, paddr) < 0)
				paddr[0] = '\0';

			/* compare the names and addresses */
			if ((prom_strcmp(name, pname) == 0) &&
			    (prom_strcmp(addr, paddr) == 0)) {
				CIF_DBG_NODE("found dev: %s%s%s (0x%x)\n",
				    pname, (*paddr != '\0') ? "@" : "",
				    paddr, np);
				break;
			} else {
				CIF_DBG_NODE("  no match: %s%s%s vs %s%s%s\n",
				    name, (*addr != '\0') ? "@" : "", addr,
				    pname, (*paddr != '\0') ? "@" : "", paddr);
			}
			np = prom_nextnode(np);
		}

		/* path does not map to a node */
		if (np == OBP_NONODE)
			break;

		if (*tp == '\0') {
			/* found a matching node */
			device = np;
			break;
		}

		/*
		 * Continue the loop with the
		 * next component of the path.
		 */
		tp++;
	}
done:

	if (device == OBP_BADNODE) {
		CIF_DBG_NODE("device not found\n\n");
	} else {
		CIF_DBG_NODE("returning 0x%x\n\n", device);
	}

	return (device);
}

#endif
