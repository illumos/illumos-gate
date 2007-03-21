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

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <sys/dld.h>
#include <libdevinfo.h>

#define	_KERNEL
#include <sys/sysmacros.h>
#undef	_KERNEL

/*
 * MAC Administration Library.
 *
 * This library is used by administration tools such as dladm(1M) to
 * iterate through the list of MAC interfaces
 *
 */

typedef struct macadm_dev {
	char			md_name[MAXNAMELEN];
	struct macadm_dev	*md_next;
} macadm_dev_t;

typedef struct macadm_walk {
	macadm_dev_t		*mw_dev_list;
} macadm_walk_t;

/*
 * Local callback invoked for each DDI_NT_NET node.
 */
/* ARGSUSED */
static int
i_macadm_apply(di_node_t node, di_minor_t minor, void *arg)
{
	macadm_walk_t	*mwp = arg;
	macadm_dev_t	*mdp = mwp->mw_dev_list;
	macadm_dev_t	**lastp = &mwp->mw_dev_list;
	char		dev[MAXNAMELEN];

	(void) snprintf(dev, MAXNAMELEN, "%s%d",
	    di_driver_name(node), di_instance(node));

	/*
	 * Skip aggregations.
	 */
	if (strcmp("aggr", di_driver_name(node)) == 0)
		return (DI_WALK_CONTINUE);

	while (mdp) {
		/*
		 * Skip duplicates.
		 */
		if (strcmp(mdp->md_name, dev) == 0)
			return (DI_WALK_CONTINUE);

		lastp = &mdp->md_next;
		mdp = mdp->md_next;
	}

	if ((mdp = malloc(sizeof (*mdp))) == NULL)
		return (DI_WALK_CONTINUE);

	(void) strlcpy(mdp->md_name, dev, MAXNAMELEN);
	mdp->md_next = NULL;
	*lastp = mdp;

	return (DI_WALK_CONTINUE);
}

/*
 * Invoke the specified callback for each DDI_NT_MAC node.
 */
int
macadm_walk(void (*fn)(void *, const char *), void *arg,
    boolean_t use_cache)
{
	di_node_t	root;
	macadm_walk_t	mw;
	macadm_dev_t	*mdp;
	uint_t		flags;

	if (use_cache) {
		flags = DINFOCACHE;
	} else {
		flags = DINFOSUBTREE | DINFOMINOR | DINFOPROP | DINFOFORCE;
	}

	if ((root = di_init("/", flags)) == DI_NODE_NIL) {
		return (-1);
	}
	mw.mw_dev_list = NULL;

	(void) di_walk_minor(root, DDI_NT_NET, DI_CHECK_ALIAS, &mw,
	    i_macadm_apply);

	di_fini(root);

	mdp = mw.mw_dev_list;
	while (mdp) {
		(*fn)(arg, mdp->md_name);
		mdp = mdp->md_next;
	}

	return (0);
}
