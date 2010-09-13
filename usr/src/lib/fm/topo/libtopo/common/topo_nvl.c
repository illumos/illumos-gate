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

#include <umem.h>
#include <topo_alloc.h>
#include <topo_module.h>

/*ARGSUSED*/
void *
topo_nv_alloc(nv_alloc_t *nva, size_t size)
{
	return (topo_zalloc(size, UMEM_DEFAULT));
}

/*ARGSUSED*/
void
topo_nv_free(nv_alloc_t *nva, void *data, size_t size)
{
	topo_free(data, size);
}

int
topo_mod_nvalloc(topo_mod_t *mod, nvlist_t **nvlp, uint_t nvflag)
{
	if (nvlist_xalloc(nvlp, nvflag, &mod->tm_alloc->ta_nva) != 0)
		return (-1);

	return (0);
}

int
topo_mod_nvdup(topo_mod_t *mod, nvlist_t *nvl, nvlist_t **nvlp)
{
	if (nvlist_xdup(nvl, nvlp, &mod->tm_alloc->ta_nva) != 0)
		return (-1);

	return (0);
}

int
topo_hdl_nvalloc(topo_hdl_t *thp, nvlist_t **nvlp, uint_t nvflag)
{

	if (nvlist_xalloc(nvlp, nvflag, &thp->th_alloc->ta_nva) != 0)
		return (-1);

	return (0);
}

int
topo_hdl_nvdup(topo_hdl_t *thp, nvlist_t *nvl, nvlist_t **nvlp)
{
	if (nvlist_xdup(nvl, nvlp, &thp->th_alloc->ta_nva) != 0)
		return (-1);

	return (0);
}
