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
#include <stropts.h>
#include <sys/dld.h>
#include <libdevinfo.h>
#include <libdladm.h>
#include <libdlpi.h>

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

typedef struct macadm_walk {
	void	*mw_arg;
	void	(*mw_fn)(void *, const char *);
} macadm_walk_t;

/*
 * Local callback invoked for each DDI_NT_NET node.
 */
/* ARGSUSED */
static int
i_macadm_apply(di_node_t node, di_minor_t minor, void *arg)
{
	macadm_walk_t	*mwp = arg;
	char		dev[MAXNAMELEN];
	dladm_attr_t	dlattr;
	int		fd;

	(void) snprintf(dev, MAXNAMELEN, "%s%d",
	    di_driver_name(node), di_instance(node));

	/*
	 * We need to be able to report devices that are
	 * reported by the walker, but have not yet attached
	 * to the system. Attempting to opening them will
	 * cause them to temporarely attach and be known
	 * by dld.
	 */
	if ((fd = dlpi_open(dev)) == -1 && errno != EPERM)
		return (DI_WALK_CONTINUE);
	if (fd != 0)
		(void) dlpi_close(fd);

	/* invoke callback only for non-legacy devices */
	if (dladm_info(dev, &dlattr) == 0)
		mwp->mw_fn(mwp->mw_arg, dev);

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
	uint_t	flags;

	if (use_cache) {
		flags = DINFOCACHE;
	} else {
		flags = DINFOSUBTREE | DINFOMINOR | DINFOPROP | DINFOFORCE;
	}

	if ((root = di_init("/", flags)) == DI_NODE_NIL) {
		return (-1);
	}

	mw.mw_fn = fn;
	mw.mw_arg = arg;

	(void) di_walk_minor(root, DDI_NT_NET, 0, &mw, i_macadm_apply);
	di_fini(root);

	return (0);
}
