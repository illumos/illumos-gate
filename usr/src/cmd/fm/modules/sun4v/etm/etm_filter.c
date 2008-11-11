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

/*
 * etm_filter.c
 * Description:
 *    Find the ldom that own the resource specified in the detector field
 *    of the ereport.
 */

#include <pthread.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fm/ldom.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <fm/topo_hc.h>

#include "etm_filter.h"

static etm_prc_t *etm_rcs;		/* vector of root complexes */
static uint16_t etm_rc_cnt;		/* count of rc entries in rcs */
static uint16_t etm_rc_max;		/* max entries allowed in rcs */
static pthread_mutex_t etm_rc_lock;	/* lock of the rc vector */


extern ldom_hdl_t *etm_lhp;		/* libldom handle */

/* ARGSUSED */
static int
etm_pciexrc_walker(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	int		i;			/* temp counter */
	int		n;			/* temp size of new vector */
	int		err;			/* temp error var */
	char		*str;			/* topo node value */
	fmd_hdl_t	*hdl = arg;		/* etm mod hdl */
	etm_prc_t	*rcl;			/* root complex vector */
	etm_prc_t	*p;			/* temp pointer */
	topo_instance_t	ins;			/* rc id */
	uint64_t	ba;			/* bus address */

	/* pciexrc node */
	if (strcmp(topo_node_name(node), PCIEX_ROOT) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_string(node, TOPO_PGROUP_IO, TOPO_IO_DEV, &str,
	    &err) != 0)
		return (TOPO_WALK_NEXT);

	/* physical id and bus address of a root complex */
	ins = topo_node_instance(node);
	(void) sscanf(str, "/pci@%llx", &ba);
	topo_hdl_strfree(thp, str);

	/*
	 * prc vector is full, so double its size
	 */
	if (etm_rc_cnt >= etm_rc_max) {
		n = (etm_rc_max == 0) ? 1 : 2 * etm_rc_max;
		rcl = fmd_hdl_zalloc(hdl, n * sizeof (etm_prc_t), FMD_SLEEP);
		for (i = 0, p = rcl; i < n; i++, p++) {
			p->prc_id = -1;
			p->prc_status = -1;
		}
		if (etm_rcs != NULL) {
			bcopy(etm_rcs, rcl, etm_rc_max * sizeof (etm_prc_t));
			fmd_hdl_free(hdl, etm_rcs,
			    etm_rc_max * sizeof (etm_prc_t));
		}
		etm_rcs = rcl;
		etm_rc_max = n;
	}

	if (etm_rc_cnt >= etm_rc_max) {
		fmd_hdl_abort(hdl, "rcs is full. Expect counter value %d<%d\n",
		    etm_rc_cnt, etm_rc_max);
	}

	/* Add the rc at the end of the list */
	p = etm_rcs + etm_rc_cnt;
	p->prc_id = ins;
	p->prc_cfg_handle = ba;
	etm_rc_cnt++;

	return (TOPO_WALK_NEXT);
}

/*
 * etm_pciexrc_init()
 * Description:
 *    Walk through the topology to find the pciexrc nodes. Then save the
 *    physical instances and bus addreses in a vector.
 */
static void
etm_pciexrc_init(fmd_hdl_t *hdl)
{
	topo_hdl_t	*thp;			/* topo handle */
	topo_walk_t	*twp;			/* topo walk handle */
	int		err;			/* topo error */

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return;
	twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC, etm_pciexrc_walker,
	    (void *) hdl, &err);
	if (twp == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return;
	}
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
}

/*
 * etm_update_prc()
 * Description:
 *    Query ldmd for the ldom id
 */
void
etm_update_prc(fmd_hdl_t *hdl, etm_prc_t *prc)
{
	char		name[MAX_LDOM_NAME];	/* domain name */
	uint64_t	virt_cfg_handle;	/* bus address from ldmd */
	uint64_t	did;			/* domain id */

	if (prc == NULL)
		return;

	/* call libldom to find the ldom id */
	prc->prc_status = ldom_find_id(etm_lhp, prc->prc_cfg_handle,
	    LDOM_RSRC_PCI, &virt_cfg_handle, name, MAX_LDOM_NAME, &did);
	if (prc->prc_status) {
		return;
	}

	/* cache the ldom id */
	prc->prc_did = did;
	if (prc->prc_name != NULL) {
		fmd_hdl_free(hdl, prc->prc_name, prc->prc_name_sz);
	}
	prc->prc_name_sz = strlen(name) + 1;
	prc->prc_name = fmd_hdl_zalloc(hdl, prc->prc_name_sz, FMD_SLEEP);
	(void) strncpy(prc->prc_name, name, prc->prc_name_sz);
}

/*
 * etm_find_ldom_id()
 * Description:
 *    Find the ldom name and the domain id that owns the resource specified in
 *    the ereport detector
 */
int
etm_filter_find_ldom_id(fmd_hdl_t *hdl, nvlist_t *evp, char *name,
    int name_size, uint64_t *did)
{
	char		*str;			/* temp string */
	char		*s;			/* temp string */
	int		i;			/* loop counter */
	int		ins;			/* instance number */
	nvlist_t	*det;			/* ereport detector */
	nvlist_t	**hcl;			/* hc name-value pair list */
	uint_t		sz;			/* size of hcl */
	etm_prc_t	*prc;			/* root complex */

	/* check paramters */
	if (name == NULL || name_size <= 0) {
		fmd_hdl_debug(hdl, "Invalid parameters");
		return (-1);
	}

	/* must be an ereport */
	if ((nvlist_lookup_string(evp, FM_CLASS, &str) != 0) ||
	    (strncmp(str, FM_EREPORT_CLASS, strlen(FM_EREPORT_CLASS)) != 0)) {
		fmd_hdl_debug(hdl, "not an ereport");
		return (-1);
	}

	/* the detector is of hc-scheme */
	if (nvlist_lookup_nvlist(evp, FM_EREPORT_DETECTOR, &det) != 0) {
		fmd_hdl_debug(hdl, "ereport detector not found");
		return (-1);
	}
	if ((nvlist_lookup_string(det, FM_FMRI_SCHEME, &str) != 0) ||
	    (strcmp(str, FM_FMRI_SCHEME_HC) != 0)) {
		fmd_hdl_debug(hdl, "detector is not hc-schemed\n");
		return (-1);
	}

	/*
	 * Find the pciexrc and extract the instance number
	 */
	if (nvlist_lookup_nvlist_array(det, FM_FMRI_HC_LIST, &hcl, &sz) != 0) {
		fmd_hdl_debug(hdl, "%s is not found\n", FM_FMRI_HC_LIST);
		return (-1);
	}
	for (i = 0; i < sz; i++) {
		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &str) == 0 &&
		    nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &s) == 0 &&
		    strcmp(str, PCIEX_ROOT) == 0) {
			(void) sscanf(s, "%d", &ins);
			break;
		}
	}
	if (i >= sz) {
		fmd_hdl_debug(hdl, "%s not found\n", PCIEX_ROOT);
		return (-1);
	}

	(void) pthread_mutex_lock(&etm_rc_lock);

	/* search the entry by the physical instance number */
	for (i = 0, prc = etm_rcs; prc != NULL && i < etm_rc_cnt;
	    i++, prc++) {
		if (prc->prc_id == ins) {
			/* update the cached entry */
			if (prc->prc_status != 0) {
				etm_update_prc(hdl, prc);
			}
			/* check for cached ldom name */
			if (prc->prc_status == 0 && prc->prc_name != NULL) {
				*did = prc->prc_did;
				(void) strncpy(name, prc->prc_name, name_size);
				(void) pthread_mutex_unlock(&etm_rc_lock);
				return (0);
			}
			break;
		}
	}
	if (i >= etm_rc_cnt) {
		fmd_hdl_debug(hdl, "prc[%d] not found\n", ins);
	}

	(void) pthread_mutex_unlock(&etm_rc_lock);

	return (-1);
} /* etm_find_ldom_id */

/*
 * etm_find_ldom_name()
 * Description:
 *    Find the ldom name of a given domain id (did)
 */
int
etm_filter_find_ldom_name(fmd_hdl_t *hdl, uint64_t did, char *name,
    int name_size)
{
	int		rc = -1;		/* return value */
	int		i;			/* loop counter */
	etm_prc_t	*prc;			/* root complex */

	(void) pthread_mutex_lock(&etm_rc_lock);

	/* visit all the root complexes to find an entry that matches the did */
	for (i = 0, prc = etm_rcs; prc != NULL && i < etm_rc_cnt;
	    i++, prc++) {
		/* update the cached entry */
		if (prc->prc_status != 0) {
			etm_update_prc(hdl, prc);
		}
		/* find the cached ldom name */
		if (prc->prc_status == 0 && prc->prc_did == did) {
			rc = 0;
			(void) strncpy(name, prc->prc_name ? prc->prc_name : "",
			    name_size);
			break;
		}
	}

	(void) pthread_mutex_unlock(&etm_rc_lock);

	return (rc);
} /* etm_find_ldom_name */

/*
 * etm_filter_handle_ldom_event()
 * Description:
 *    Invalidate the ldom name in the physical root complex vector.
 */
void
etm_filter_handle_ldom_event(fmd_hdl_t *hdl, etm_async_event_type_t event,
    char *name) {
	int		i;			/* loop counter */
	etm_prc_t	*prc;			/* root complex */

	/*
	 * Clear the cached ldom name
	 */
	switch (event) {
	case ETM_ASYNC_EVENT_LDOM_ADD:
	case ETM_ASYNC_EVENT_LDOM_REMOVE:
	case ETM_ASYNC_EVENT_LDOM_BIND:
	case ETM_ASYNC_EVENT_LDOM_UNBIND:
		(void) pthread_mutex_lock(&etm_rc_lock);
		for (i = 0, prc = etm_rcs; prc != NULL && i < etm_rc_cnt;
		    i++, prc++) {
			if (prc->prc_name != NULL &&
			    strcmp(prc->prc_name, name) == 0) {
				fmd_hdl_free(hdl, prc->prc_name,
				    prc->prc_name_sz);
				prc->prc_name = NULL;
				prc->prc_name_sz = 0;
				prc->prc_status = -1;
			}
		}
		(void) pthread_mutex_unlock(&etm_rc_lock);
		break;
	default:
		break;
	}
}

/* ARGSUSED */
void
etm_filter_init(fmd_hdl_t *hdl) {
	etm_rcs = NULL;
	etm_rc_cnt = 0;
	etm_rc_max = 0;
	(void) pthread_mutex_init(&etm_rc_lock, NULL);
	etm_pciexrc_init(hdl);
}

void
etm_filter_fini(fmd_hdl_t *hdl) {
	int		i;			/* loop counter */
	etm_prc_t	*prc;			/* root complex pointer */

	for (i = 0, prc = etm_rcs; prc != NULL && i < etm_rc_cnt;
	    i++, prc++) {
		if (prc->prc_name != NULL) {
			fmd_hdl_free(hdl, prc->prc_name, prc->prc_name_sz);
			prc->prc_name = NULL;
			prc->prc_name_sz = 0;
			prc->prc_status = -1;
		}
	}
	if (etm_rcs != NULL && etm_rc_max > 0) {
		fmd_hdl_free(hdl, etm_rcs, etm_rc_max * sizeof (etm_prc_t));
	}
	(void) pthread_mutex_destroy(&etm_rc_lock);
}
