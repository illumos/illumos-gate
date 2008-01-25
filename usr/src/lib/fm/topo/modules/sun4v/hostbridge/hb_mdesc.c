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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <strings.h>
#include <umem.h>
#include <sys/mdesc.h>
#include <sys/systeminfo.h>
#include <sys/fm/ldom.h>

#include <hb_mdesc.h>

#include "hb_rcid.h"

static void *
hb_alloc(size_t size)
{
	return (umem_alloc(size, UMEM_DEFAULT));
}

static void
hb_free(void *data, size_t size)
{
	umem_free(data, size);
}

/*
 * hb_find_hb()
 * Description:
 *     Return the pointer of hostbridge entry
 */
md_hb_t *
hb_find_hb(md_info_t *phbmd, int hbid) {
	int i;
	md_hb_t *phb;

	/* search the processor based on the physical id */
	for (i = 0, phb = phbmd->hbs; i < phbmd->nhbs; i++, phb++) {
		if (phb->rcs != NULL && phb->id == hbid) {
			return (phb);
		}
	}

	return (NULL);
}

/*
 * hb_rc_init()
 * Description:
 *     Read the hostbridge/pciexrc information from the MD
 *     The hostbridge/pciexrc information is not specified in the PRI of
 *     the existing sun4v platforms, the enumerator assumes there is only
 *     one hostbridge and its physical id is 0. It will create all the
 *     pciexrc nodes under the topo node hostbridge=0.
 */
static int
hb_rc_init(topo_mod_t *mod, md_t *mdp, md_info_t *hbmdp)
{
	int i, rc;
	int id, nnode, nio, nrcs;
	char *s = NULL;
	uint64_t x;
	mde_cookie_t *listp;
	md_hb_t *hbp;
	char platform[MAXNAMELEN];

	bzero(hbmdp, sizeof (md_info_t));
	nnode = md_node_count(mdp);
	listp = topo_mod_zalloc(mod, sizeof (mde_cookie_t) * nnode);

	/* find the pciex bus nodes */
	nio = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, MD_STR_IODEVICE),
	    md_find_name(mdp, "fwd"),
	    listp);
	if (nio <= 0) {
		topo_mod_dprintf(mod, "iodevice nodes not found\n");
		topo_mod_free(mod, listp, sizeof (mde_cookie_t) * nnode);
		return (-1);
	}
	topo_mod_dprintf(mod, "Found %d %s nodes\n", nio, MD_STR_IODEVICE);

	for (i = 0, nrcs = 0; i < nio; i++) {
		rc = md_get_prop_str(mdp, listp[i], MD_STR_DEVICE_TYPE, &s);
		if ((rc == 0) && (s != NULL) && (strcmp(s, MD_STR_PCIEX) == 0))
			nrcs++;
	}
	topo_mod_dprintf(mod, "Found %d pciex buses\n", nrcs);
	if (nrcs == 0) {
		topo_mod_dprintf(mod, "pciex nodes not found\n");
		topo_mod_free(mod, listp, sizeof (mde_cookie_t) * nnode);
		return (-1);
	}

	platform[0] = '\0';
	(void) sysinfo(SI_PLATFORM, platform, sizeof (platform));

	/*
	 * All existing sun4v platforms have only one hostdridge.
	 */
	hbmdp->shbs = hbmdp->nhbs = 1;
	hbp = topo_mod_zalloc(mod, sizeof (md_hb_t) * hbmdp->nhbs);
	hbp->id = 0;
	hbmdp->hbs = hbp;

	hbp->srcs = nrcs;
	hbp->rcs = topo_mod_zalloc(mod, sizeof (md_rc_t) * nrcs);
	hbp->nrcs = 0;
	for (i = 0, nrcs = 0; i < nio; i++) {
		rc = md_get_prop_str(mdp, listp[i], MD_STR_DEVICE_TYPE, &s);
		if ((rc != 0) || s == NULL || strcmp(s, MD_STR_PCIEX) != 0)
			continue;

		hbp->rcs[nrcs].id = -1;		/* invalidate the entry */

		/* bus address */
		if (md_get_prop_val(mdp, listp[i], MD_STR_CFGHDL, &x) < 0) {
			nrcs++;
			continue;
		}
		hbp->rcs[nrcs].cfg_handle = x;
		topo_mod_dprintf(mod, "Found rc=%d ba=%llx\n", nrcs, x);

		/* Assign the physical id of the pciexrc */
		if ((id = hb_find_rc_pid(platform, x)) >= 0)
			hbp->rcs[nrcs].id = id;
		else
			hbp->rcs[nrcs].id = hbp->nrcs;

		nrcs++;
		hbp->nrcs++;
	}

	topo_mod_free(mod, listp, sizeof (mde_cookie_t) * nnode);

	return (0);
}

/*
 * Get the info. of the hb and rc from the PRI/MD
 */
int
hb_mdesc_init(topo_mod_t *mod, md_info_t *phbmd)
{
	int rc = -1;
	md_t *mdp;
	ssize_t bufsiz = 0;
	uint64_t *bufp;
	ldom_hdl_t *lhp;

	/* get the PRI/MD */
	if ((lhp = ldom_init(hb_alloc, hb_free)) == NULL) {
		topo_mod_dprintf(mod, "ldom_init() failed\n");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	if ((bufsiz = ldom_get_core_md(lhp, &bufp)) <= 0) {
		topo_mod_dprintf(mod, "failed to get the PRI/MD\n");
		ldom_fini(lhp);
		return (-1);
	}

	if ((mdp = md_init_intern(bufp, hb_alloc, hb_free)) == NULL ||
	    md_node_count(mdp) <= 0) {
		hb_free(bufp, (size_t)bufsiz);
		ldom_fini(lhp);
		return (-1);
	}

	rc = hb_rc_init(mod, mdp, phbmd);

	hb_free(bufp, (size_t)bufsiz);
	(void) md_fini(mdp);
	ldom_fini(lhp);

	return (rc);
}

void
hb_mdesc_fini(topo_mod_t *mod, md_info_t *hbmdp)
{
	int i;
	md_hb_t *hbp;

	if (hbmdp->hbs == NULL)
		return;

	for (i = 0, hbp = hbmdp->hbs; i < hbmdp->nhbs; i++, hbp++) {
		if (hbp->rcs == NULL)
			continue;
		topo_mod_free(mod, hbp->rcs, hbp->srcs * sizeof (md_rc_t));
	}
	topo_mod_free(mod, hbmdp->hbs, hbmdp->shbs * sizeof (md_hb_t));

}
