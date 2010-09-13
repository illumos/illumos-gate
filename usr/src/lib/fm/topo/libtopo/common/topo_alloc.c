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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <umem.h>
#include <strings.h>

#include <topo_alloc.h>

void *
topo_alloc(size_t size, int flags)
{
	return (umem_alloc(size, flags));
}

/*ARGSUSED*/
void *
topo_zalloc(size_t size, int flags)
{
	void *data = topo_alloc(size, flags);
	if (data != NULL)
		bzero(data, size);

	return (data);
}

void
topo_free(void *data, size_t size)
{
	umem_free(data, size);
}

void *
topo_hdl_alloc(topo_hdl_t *thp, size_t size)
{
	topo_alloc_t *ap = thp->th_alloc;

	return (ap->ta_alloc(size, ap->ta_flags));
}

void *
topo_hdl_zalloc(topo_hdl_t *thp, size_t size)
{
	topo_alloc_t *ap = thp->th_alloc;

	return (ap->ta_zalloc(size, ap->ta_flags));
}

void
topo_hdl_free(topo_hdl_t *thp, void *data, size_t size)
{
	topo_alloc_t *ap = thp->th_alloc;

	ap->ta_free(data, size);
}

void *
topo_mod_alloc(topo_mod_t *mod, size_t size)
{
	return (topo_hdl_alloc(mod->tm_hdl, size));
}

void *
topo_mod_zalloc(topo_mod_t *mod, size_t size)
{
	return (topo_hdl_zalloc(mod->tm_hdl, size));
}

void
topo_mod_free(topo_mod_t *mod, void *data, size_t size)
{
	topo_hdl_free(mod->tm_hdl, data, size);
}
