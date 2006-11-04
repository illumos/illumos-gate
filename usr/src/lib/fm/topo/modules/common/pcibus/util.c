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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <fm/libtopo.h>

int
child_range_add(topo_mod_t *mp, tnode_t *tn, const char *cnm,
    topo_instance_t imin, topo_instance_t imax)
{
	int e;

	e = topo_node_range_create(mp, tn, cnm, imin, imax);
	if (e != 0) {
		topo_mod_dprintf(mp, "add child range (%s) failed: %s\n",
		    cnm, topo_strerror(topo_mod_errno(mp)));
		return (-1);
	}
	return (0);
}

ulong_t
strtonum(topo_mod_t *mp, char *str, int *err)
{
	ulong_t r;
	char *e;

	r = strtoul(str, &e, 16);
	if (e == str) {
		topo_mod_dprintf(mp,
		    "Trouble converting %s to a number!\n", str);
		*err = -1;
		return (0);
	}
	*err = 0;
	return (r);
}

tnode_t *
tnode_create(topo_mod_t *mp, tnode_t *parent,
    const char *name, topo_instance_t i, void *priv)
{
	nvlist_t *fmri;
	tnode_t *ntn;
	nvlist_t *auth;

	auth = topo_mod_auth(mp, parent);
	fmri = topo_mod_hcfmri(mp, parent, FM_HC_SCHEME_VERSION, name, i, NULL,
	    auth, NULL, NULL, NULL);
	nvlist_free(auth);
	if (fmri == NULL) {
		topo_mod_dprintf(mp,
		    "Unable to make nvlist for %s bind.\n", name);
		return (NULL);
	}

	ntn = topo_node_bind(mp, parent, name, i, fmri);
	if (ntn == NULL) {
		topo_mod_dprintf(mp,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mp)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	topo_node_setspecific(ntn, priv);

	return (ntn);
}

/*ARGSUSED*/
int
labelmethod_inherit(topo_mod_t *mp, tnode_t *tn, nvlist_t *in, nvlist_t **out)
{
	int err;

	/*
	 * Ignore the input and output nvlists and directly set the
	 * label as inheritance from the parent
	 */
	*out = NULL;
	if (topo_node_label_set(tn, NULL, &err) < 0) {
		if (err != ETOPO_PROP_NOENT)
			return (topo_mod_seterrno(mp, err));
	}
	return (0);
}
