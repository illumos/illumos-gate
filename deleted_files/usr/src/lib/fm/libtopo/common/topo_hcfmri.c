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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <libnvpair.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include "topo_impl.h"
#include "libtopo.h"

static char instbuf[MAXINSTLEN];

nvlist_t *
build_fmri(tnode_t *n, nvlist_t **nvl, uint_t sz, uint_t idx)
{
	nvlist_t *f = NULL;
	nvlist_t *p = NULL;
	int e;

	if (n == NULL || n->state == TOPO_ROOT) {
		errno = nvlist_xalloc(&f, NV_UNIQUE_NAME, &Topo_nv_alloc_hdl);
		if (errno != 0) {
			topo_out(TOPO_ERR, "alloc of big nvl failed:");
			return (NULL);
		}
		e = nvlist_add_string(f, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
		e |= nvlist_add_uint8(f, FM_VERSION, FM_HC_SCHEME_VERSION);
		e |= nvlist_add_string(f, FM_FMRI_HC_ROOT, "");
		e |= nvlist_add_uint32(f, FM_FMRI_HC_LIST_SZ, sz);
		e |= nvlist_add_nvlist_array(f, FM_FMRI_HC_LIST, nvl, sz);
		if (e == 0)
			return (f);
		topo_out(TOPO_ERR, "construct of big nvl failed:");
		nvlist_free(f);
		return (NULL);
	}

	if (n->state != TOPO_INST)
		return (NULL);

	idx--;
	(void) snprintf(instbuf, MAXINSTLEN, "%d", n->u.inst);

	errno = nvlist_xalloc(&p, NV_UNIQUE_NAME, &Topo_nv_alloc_hdl);
	if (errno != 0) {
		topo_out(TOPO_ERR, "alloc of an hc-pair failed:");
		return (NULL);
	}
	e = nvlist_add_string(p, FM_FMRI_HC_NAME, topo_name(n));
	e |= nvlist_add_string(p, FM_FMRI_HC_ID, instbuf);
	if (e != 0) {
		topo_out(TOPO_ERR, "construct of hc-pair failed:");
		nvlist_free(p);
		return (NULL);
	}
	nvl[idx] = p;
	return (build_fmri(topo_parent(n), nvl, sz, idx));
}

nvlist_t *
topo_hc_fmri(tnode_t *tothisnode)
{
	const char *nam, *val;
	nvlist_t **nvl = NULL;
	nvlist_t *r;
	uint_t sz;

	sz = tnode_depth(tothisnode);
	if (sz < 1)
		return (NULL);

	/*
	 * The final fmri will contain sz nvlists, each list having
	 * an hc-name, hc-id pair.
	 */
	nvl = topo_zalloc(sz * sizeof (nvlist_t *));

	if ((r = build_fmri(tothisnode, nvl, sz, sz)) == NULL)
		goto out;

	/* now add the properties */
	nam = NULL;
	errno = 0;
	while ((nam = topo_next_prop(tothisnode, nam)) != NULL) {
		val = topo_get_prop(tothisnode, nam);
		if ((errno = nvlist_add_string(r, nam, val)) != 0) {
			nvlist_free(r);
			break;
		}
	}

out:
	free(nvl);
	return (r);
}
