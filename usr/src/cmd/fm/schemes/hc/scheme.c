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

#include <strings.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>

int
fmd_fmri_init(void)
{
	return (0);
}

void
fmd_fmri_fini(void)
{
}

ssize_t
fmd_fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	int err;
	uint8_t version;
	ssize_t len;
	topo_hdl_t *thp;
	char *str;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_HC_SCHEME_VERSION)
		return (fmd_fmri_set_errno(EINVAL));

	thp = fmd_fmri_topology(TOPO_VERSION);
	if (topo_fmri_nvl2str(thp, nvl, &str, &err) != 0)
		return (fmd_fmri_set_errno(EINVAL));

	if (buf != NULL)
		len = snprintf(buf, buflen, "%s", str);
	else
		len = strlen(str);

	topo_hdl_strfree(thp, str);

	return (len);
}

typedef struct hc_walk_arg {
	void	*p;
	int	*resultp;
} hc_walk_arg_t;

static int
hc_topo_walk(topo_hdl_t *thp, topo_walk_cb_t fn, void *arg, int *resultp)
{
	int err, rv;
	topo_walk_t *twp;
	hc_walk_arg_t hcarg;

	hcarg.p = arg;
	hcarg.resultp = resultp;

	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, fn,
	    &hcarg, &err)) == NULL)
		return (-1);

	rv = (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR)
	    ? -1 : 0;

	topo_walk_fini(twp);
	return (rv);
}

/*ARGSUSED*/
static int
hc_topo_present(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int cmp, err;
	nvlist_t *out, *asru;
	hc_walk_arg_t *hcargp = (hc_walk_arg_t *)arg;

	/*
	 * Only care about sata-ports and disks
	 */
	if (strcmp(topo_node_name(node), SATA_PORT) != 0 &&
	    strcmp(topo_node_name(node), DISK) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_node_asru(node, &asru, NULL, &err) != 0 ||
	    asru == NULL) {
		return (TOPO_WALK_NEXT);
	}

	/*
	 * Check if the ASRU of this node matches the ASRU passed in
	 */
	cmp = topo_fmri_compare(thp, asru, (nvlist_t *)hcargp->p, &err);

	nvlist_free(asru);

	if (cmp <= 0)
		return (TOPO_WALK_NEXT);

	/*
	 * Yes, so try to execute the topo-present method.
	 */
	if (topo_method_invoke(node, TOPO_METH_PRESENT,
	    TOPO_METH_PRESENT_VERSION, (nvlist_t *)hcargp->p, &out, &err)
	    == 0) {
		(void) nvlist_lookup_uint32(out, TOPO_METH_PRESENT_RET,
		    (uint32_t *)hcargp->resultp);
		nvlist_free(out);
		return (TOPO_WALK_TERMINATE);
	} else {
		return (TOPO_WALK_ERR);
	}

}

/*
 * The SATA disk topology permits an ASRU to be declared as a pseudo-hc
 * FMRI, something like this:
 *
 *	hc:///motherboard=0/hostbridge=0/pcibus=0/pcidev=1/pcifn=0/sata-port=1
 *		ASRU: hc:///component=sata0/1
 *		FRU: hc:///component=MB
 *		Label: sata0/1
 *
 * This is a hack to support cfgadm attachment point ASRUs without defining
 * a new scheme.  As a result, we need to support an is_present function for
 * something * that begins with hc:///component=.  To do this, we compare the
 * nvlist provided by the caller against the ASRU property for all possible
 * topology nodes.
 *
 * The SATA phase 2 project will address the lack of a proper FMRI scheme
 * for cfgadm attachment points.  This code may be removed when the SATA
 * phase 2 FMA work is completed.
 */
static int
hc_sata_hack(nvlist_t *nvl)
{
	int ispresent = 1;
	topo_hdl_t *thp;

	/*
	 * If there's an error during the topology update, punt by
	 * indicating presence.
	 */
	thp = fmd_fmri_topology(TOPO_VERSION);
	(void) hc_topo_walk(thp, hc_topo_present, nvl, &ispresent);

	return (ispresent);
}

int
fmd_fmri_present(nvlist_t *nvl)
{
	int err, present;
	topo_hdl_t *thp;
	nvlist_t **hcprs;
	char *nm;
	uint_t hcnprs;

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	err |= nvlist_lookup_string(hcprs[0], FM_FMRI_HC_NAME, &nm);
	if (err != 0)
		return (0);

	if (strcmp(nm, "component") == 0)
		return (hc_sata_hack(nvl));

	thp = fmd_fmri_topology(TOPO_VERSION);
	present = topo_fmri_present(thp, nvl, &err);

	if (err != 0)
		return (present);
	else
		return (1);
}

/*
 * fmd_fmri_unusable() is called by fmadm to determine if a faulty ASRU
 * is usable.  In general we don't expect to get ASRUs in this scheme,
 * so it's unlikely this routine will get called.  In case it does,
 * though, we just return false by default, as we have no real way to
 * find the component or determine the component's usability.
 */
/*ARGSUSED*/
int
fmd_fmri_unusable(nvlist_t *nvl)
{
	return (0);
}
