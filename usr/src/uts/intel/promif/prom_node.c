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
#include <sys/kmem.h>

/*
 * Routines for walking the PROMs devinfo tree
 * The prom tree is for /dev/openprom compatibility only,
 * so we fail all calls except those needed by /dev/openprom
 */

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
prom_nextnode(pnode_t nodeid)
{
	return (promif_nextnode(nodeid));
}

pnode_t
prom_childnode(pnode_t nodeid)
{

	return (promif_childnode(nodeid));
}

/*
 * disallow searching
 */
/*ARGSUSED*/
pnode_t
prom_findnode_byname(pnode_t n, char *name)
{
	return (OBP_NONODE);
}

pnode_t
prom_chosennode(void)
{
	return (OBP_NONODE);
}

pnode_t
prom_optionsnode(void)
{
	return (OBP_NONODE);
}

/*ARGSUSED*/
pnode_t
prom_finddevice(char *path)
{
	return (OBP_BADNODE);
}

pnode_t
prom_alias_node(void)
{
	return (OBP_BADNODE);
}

/*ARGSUSED*/
void
prom_pathname(char *buf)
{
	/* nothing, just to get consconfig_dacf to compile */
}
