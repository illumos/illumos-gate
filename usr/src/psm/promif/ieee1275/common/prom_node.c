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

/*
 * Routines for walking the PROMs devinfo tree
 */
pnode_t
prom_nextnode(pnode_t nodeid)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("peer");		/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_dnode2cell(nodeid);	/* Arg1: input phandle */
	ci[4] = p1275_dnode2cell(OBP_NONODE);	/* Res1: Prime result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2dnode(ci[4]));	/* Res1: peer phandle */
}

pnode_t
prom_childnode(pnode_t nodeid)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("child");	/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_dnode2cell(nodeid);	/* Arg1: input phandle */
	ci[4] = p1275_dnode2cell(OBP_NONODE);	/* Res1: Prime result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2dnode(ci[4]));	/* Res1: child phandle */
}

/*
 * prom_walk_devs() implements a generic walker for the OBP tree; this
 * implementation uses an explicitly managed stack in order to save the
 * overhead of a recursive implementation.
 */
void
prom_walk_devs(pnode_t node, int (*cb)(pnode_t, void *, void *), void *arg,
    void *result)
{
	pnode_t stack[OBP_STACKDEPTH];
	int stackidx = 0;

	if (node == OBP_NONODE || node == OBP_BADNODE) {
		prom_panic("Invalid node specified as root of prom tree walk");
	}

	stack[0] = node;

	for (;;) {
		pnode_t curnode = stack[stackidx];
		pnode_t child;

		/*
		 * We're out of stuff to do at this level, bump back up a level
		 * in the tree, and move to the next node;  if the new level
		 * will be level -1, we're done.
		 */
		if (curnode == OBP_NONODE || curnode == OBP_BADNODE) {
			stackidx--;

			if (stackidx < 0)
				return;

			stack[stackidx] = prom_nextnode(stack[stackidx]);
			continue;
		}

		switch ((*cb)(curnode, arg, result)) {

		case PROM_WALK_TERMINATE:
			return;

		case PROM_WALK_CONTINUE:
			/*
			 * If curnode has a child, traverse to it,
			 * otherwise move to curnode's sibling.
			 */
			child = prom_childnode(curnode);
			if (child != OBP_NONODE && child != OBP_BADNODE) {
				stackidx++;
				stack[stackidx] = child;
			} else {
				stack[stackidx] =
				    prom_nextnode(stack[stackidx]);
			}
			break;

		default:
			prom_panic("unrecognized walk directive");
		}
	}
}

/*
 * prom_findnode_bydevtype() searches the prom device subtree rooted at 'node'
 * and returns the first node whose device type property matches the type
 * supplied in 'devtype'.
 */
static int
bytype_cb(pnode_t node, void *arg, void *result)
{
	if (prom_devicetype(node, (char *)arg)) {
		*((pnode_t *)result) = node;
		return (PROM_WALK_TERMINATE);
	}
	return (PROM_WALK_CONTINUE);
}

pnode_t
prom_findnode_bydevtype(pnode_t node, char *devtype)
{
	pnode_t result = OBP_NONODE;
	prom_walk_devs(node, bytype_cb, devtype, &result);
	return (result);
}


/*
 * prom_findnode_byname() searches the prom device subtree rooted at 'node' and
 * returns the first node whose name matches the name supplied in 'name'.
 */
static int
byname_cb(pnode_t node, void *arg, void *result)
{
	if (prom_getnode_byname(node, (char *)arg)) {
		*((pnode_t *)result) = node;
		return (PROM_WALK_TERMINATE);
	}
	return (PROM_WALK_CONTINUE);
}

pnode_t
prom_findnode_byname(pnode_t node, char *name)
{
	pnode_t result = OBP_NONODE;
	prom_walk_devs(node, byname_cb, name, &result);
	return (result);
}

/*
 * Return the root nodeid.
 * Calling prom_nextnode(0) returns the root nodeid.
 */
pnode_t
prom_rootnode(void)
{
	static pnode_t rootnode;

	return (rootnode ? rootnode : (rootnode = prom_nextnode(OBP_NONODE)));
}

pnode_t
prom_parentnode(pnode_t nodeid)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("parent");	/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_dnode2cell(nodeid);	/* Arg1: input phandle */
	ci[4] = p1275_dnode2cell(OBP_NONODE);	/* Res1: Prime result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2dnode(ci[4]));	/* Res1: parent phandle */
}

pnode_t
prom_finddevice(char *path)
{
	cell_t ci[5];
#ifdef PROM_32BIT_ADDRS
	char *opath = NULL;
	size_t len;

	if ((uintptr_t)path > (uint32_t)-1) {
		opath = path;
		len = prom_strlen(opath) + 1; /* include terminating NUL */
		path = promplat_alloc(len);
		if (path == NULL) {
			return (OBP_BADNODE);
		}
		(void) prom_strcpy(path, opath);
	}
#endif

	promif_preprom();

	ci[0] = p1275_ptr2cell("finddevice");	/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell(path);		/* Arg1: pathname */
	ci[4] = p1275_dnode2cell(OBP_BADNODE);	/* Res1: Prime result */

	(void) p1275_cif_handler(&ci);

	promif_postprom();

#ifdef PROM_32BIT_ADDRS
	if (opath != NULL)
		promplat_free(path, len);
#endif

	return ((pnode_t)p1275_cell2dnode(ci[4])); /* Res1: phandle */
}

pnode_t
prom_chosennode(void)
{
	static pnode_t chosen;
	pnode_t	node;

	if (chosen)
		return (chosen);

	node = prom_finddevice("/chosen");

	if (node != OBP_BADNODE)
		return (chosen = node);

	prom_fatal_error("prom_chosennode: Can't find </chosen>\n");
	/*NOTREACHED*/

	/*
	 * gcc doesn't recognize "NOTREACHED" and puts the warning.
	 * To surpress it, returning an integer value is required.
	 */
	return ((pnode_t)0);
}

/*
 * Returns the nodeid of /aliases.
 * /aliases exists in OBP >= 2.4 and in Open Firmware.
 * Returns OBP_BADNODE if it doesn't exist.
 */
pnode_t
prom_alias_node(void)
{
	static pnode_t node;

	if (node == 0)
		node = prom_finddevice("/aliases");
	return (node);
}

/*
 * Returns the nodeid of /options.
 * Returns OBP_BADNODE if it doesn't exist.
 */
pnode_t
prom_optionsnode(void)
{
	static pnode_t node;

	if (node == 0)
		node = prom_finddevice("/options");
	return (node);
}
