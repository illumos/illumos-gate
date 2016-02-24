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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Support routines for DIMMs.
 */

#include <gmem_mem.h>
#include <gmem_dimm.h>
#include <gmem.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>
#include <sys/nvpair.h>

nvlist_t *dimm_nvl;

typedef struct dimmid {
	char serial[100];
	int type;
} dimmid_t;

static int gmem_find_dimm_chip(nvlist_t *, uint32_t *);

nvlist_t *
gmem_dimm_fru(gmem_dimm_t *dimm)
{
	return (dimm->dimm_asru_nvl);
}

static void
gmem_dimm_free(fmd_hdl_t *hdl, gmem_dimm_t *dimm, int destroy)
{
	gmem_case_t *cc = &dimm->dimm_case;
	int i;
	gmem_mq_t *q;
	tstamp_t *tsp, *next;

	if (cc->cc_cp != NULL) {
		gmem_case_fini(hdl, cc->cc_cp, destroy);
		if (cc->cc_serdnm != NULL) {
			if (fmd_serd_exists(hdl, cc->cc_serdnm) &&
			    destroy)
				fmd_serd_destroy(hdl, cc->cc_serdnm);
			fmd_hdl_strfree(hdl, cc->cc_serdnm);
		}
	}

	gmem_fmri_fini(hdl, &dimm->dimm_asru, destroy);

	for (i = 0; i < GMEM_MAX_CKWDS; i++) {
		while ((q = gmem_list_next(&dimm->mq_root[i])) != NULL) {
			if (q->mq_serdnm != NULL) {
				if (fmd_serd_exists(hdl, q->mq_serdnm))
					fmd_serd_destroy(hdl, q->mq_serdnm);
				fmd_hdl_strfree(hdl, q->mq_serdnm);
				q->mq_serdnm = NULL;
			}

			for (tsp = gmem_list_next(&q->mq_dupce_tstamp);
			    tsp != NULL; tsp = next) {
				next = gmem_list_next(tsp);
				gmem_list_delete(&q->mq_dupce_tstamp,
				    &tsp->ts_l);
				fmd_hdl_free(hdl, tsp, sizeof (tstamp_t));
			}

			gmem_list_delete(&dimm->mq_root[i], q);
			fmd_hdl_free(hdl, q, sizeof (gmem_mq_t));
		}
	}

	if (destroy)
		fmd_buf_destroy(hdl, NULL, dimm->dimm_bufname);

	gmem_list_delete(&gmem.gm_dimms, dimm);
	fmd_hdl_free(hdl, dimm, sizeof (gmem_dimm_t));
}

void
gmem_dimm_destroy(fmd_hdl_t *hdl, gmem_dimm_t *dimm)
{
	fmd_stat_destroy(hdl, 1, &(dimm->dimm_retstat));
	gmem_dimm_free(hdl, dimm, FMD_B_TRUE);
}

static gmem_dimm_t *
dimm_lookup_by_serial(const char *serial)
{
	gmem_dimm_t *dimm;

	for (dimm = gmem_list_next(&gmem.gm_dimms); dimm != NULL;
	    dimm = gmem_list_next(dimm)) {
		if (strcmp(dimm->dimm_serial, serial) == 0)
			return (dimm);
	}

	return (NULL);
}

gmem_dimm_t *
gmem_dimm_create(fmd_hdl_t *hdl, nvlist_t *asru, nvlist_t *det)
{
	gmem_dimm_t *dimm;
	nvlist_t *fmri;
	char *serial;
	uint32_t chip_id;

	if (nvlist_lookup_string(asru, FM_FMRI_HC_SERIAL_ID, &serial) != 0) {
		fmd_hdl_debug(hdl, "Unable to get dimm serial\n");
		return (NULL);
	}

	if (nvlist_dup(asru, &fmri, 0) != 0) {
		fmd_hdl_debug(hdl, "dimm create nvlist dup failed");
		return (NULL);
	}

	(void) gmem_find_dimm_chip(det, &chip_id);

	fmd_hdl_debug(hdl, "dimm_create: creating new DIMM serial=%s\n",
	    serial);
	GMEM_STAT_BUMP(dimm_creat);

	dimm = fmd_hdl_zalloc(hdl, sizeof (gmem_dimm_t), FMD_SLEEP);
	dimm->dimm_nodetype = GMEM_NT_DIMM;
	dimm->dimm_version = GMEM_DIMM_VERSION;
	dimm->dimm_phys_addr_low = ULLONG_MAX;
	dimm->dimm_phys_addr_hi = 0;
	dimm->dimm_syl_error = USHRT_MAX;
	dimm->dimm_chipid = chip_id;

	gmem_bufname(dimm->dimm_bufname, sizeof (dimm->dimm_bufname), "dimm_%s",
	    serial);
	gmem_fmri_init(hdl, &dimm->dimm_asru, fmri, "dimm_asru_%s", serial);

	nvlist_free(fmri);

	(void) nvlist_lookup_string(dimm->dimm_asru_nvl, FM_FMRI_HC_SERIAL_ID,
	    (char **)&dimm->dimm_serial);

	gmem_mem_retirestat_create(hdl, &dimm->dimm_retstat, dimm->dimm_serial,
	    0, GMEM_DIMM_STAT_PREFIX);

	gmem_list_append(&gmem.gm_dimms, dimm);
	gmem_dimm_dirty(hdl, dimm);

	return (dimm);
}

gmem_dimm_t *
gmem_dimm_lookup(fmd_hdl_t *hdl, nvlist_t *asru)
{
	gmem_dimm_t *dimm;
	char *serial;
	int err;

	err = nvlist_lookup_string(asru, FM_FMRI_HC_SERIAL_ID, &serial);

	if (err != 0) {
		fmd_hdl_debug(hdl, "Can't get dimm serial number\n");
		GMEM_STAT_BUMP(bad_mem_resource);
		return (NULL);
	}

	dimm = dimm_lookup_by_serial(serial);
	return (dimm);
}


static gmem_dimm_t *
gmem_dimm_v0tov1(fmd_hdl_t *hdl, gmem_dimm_0_t *old, size_t oldsz)
{
	gmem_dimm_t *new;
	if (oldsz != sizeof (gmem_dimm_0_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (gmem_dimm_0_t));
	}

	new = fmd_hdl_zalloc(hdl, sizeof (gmem_dimm_t), FMD_SLEEP);
	new->dimm_header = old->dimm0_header;
	new->dimm_version = GMEM_DIMM_VERSION;
	new->dimm_asru = old->dimm0_asru;
	new->dimm_nretired = old->dimm0_nretired;
	new->dimm_phys_addr_hi = 0;
	new->dimm_phys_addr_low = ULLONG_MAX;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static gmem_dimm_t *
gmem_dimm_wrapv1(fmd_hdl_t *hdl, gmem_dimm_pers_t *pers, size_t psz)
{
	gmem_dimm_t *dimm;

	if (psz != sizeof (gmem_dimm_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (gmem_dimm_pers_t));
	}

	dimm = fmd_hdl_zalloc(hdl, sizeof (gmem_dimm_t), FMD_SLEEP);
	bcopy(pers, dimm, sizeof (gmem_dimm_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (dimm);
}

void *
gmem_dimm_restore(fmd_hdl_t *hdl, fmd_case_t *cp, gmem_case_ptr_t *ptr)
{
	gmem_dimm_t *dimm;

	for (dimm = gmem_list_next(&gmem.gm_dimms); dimm != NULL;
	    dimm = gmem_list_next(dimm)) {
		if (strcmp(dimm->dimm_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (dimm == NULL) {
		int migrated = 0;
		size_t dimmsz;

		fmd_hdl_debug(hdl, "restoring dimm from %s\n", ptr->ptr_name);

		if ((dimmsz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
			fmd_hdl_abort(hdl, "dimm referenced by case %s does "
			    "not exist in saved state\n",
			    fmd_case_uuid(hdl, cp));
		} else if (dimmsz > GMEM_DIMM_MAXSIZE ||
		    dimmsz < GMEM_DIMM_MINSIZE) {
			fmd_hdl_abort(hdl, "dimm buffer referenced by case %s "
			    "is out of bounds (is %u bytes, max %u, min %u)\n",
			    fmd_case_uuid(hdl, cp), dimmsz,
			    GMEM_DIMM_MAXSIZE, GMEM_DIMM_MINSIZE);
		}

		if ((dimm = gmem_buf_read(hdl, NULL, ptr->ptr_name,
		    dimmsz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read dimm buf %s",
			    ptr->ptr_name);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    dimm->dimm_version);

		if (GMEM_DIMM_VERSIONED(dimm)) {

			switch (dimm->dimm_version) {
			case GMEM_DIMM_VERSION_1:
				dimm = gmem_dimm_wrapv1(hdl,
				    (gmem_dimm_pers_t *)dimm, dimmsz);
				break;
			default:
				fmd_hdl_abort(hdl, "unknown version (found %d) "
				    "for dimm state referenced by case %s.\n",
				    dimm->dimm_version, fmd_case_uuid(hdl, cp));
				break;
			}
		} else {
			dimm = gmem_dimm_v0tov1(hdl, (gmem_dimm_0_t *)dimm,
			    dimmsz);
			migrated = 1;
		}

		if (migrated) {
			GMEM_STAT_BUMP(dimm_migrat);
			gmem_dimm_dirty(hdl, dimm);
		}

		gmem_fmri_restore(hdl, &dimm->dimm_asru);

		if ((errno = nvlist_lookup_string(dimm->dimm_asru_nvl,
		    FM_FMRI_HC_SERIAL_ID, (char **)&dimm->dimm_serial)) != 0)
			fmd_hdl_abort(hdl,
			    "failed to retrieve serial from asru");


		gmem_mem_retirestat_create(hdl, &dimm->dimm_retstat,
		    dimm->dimm_serial, dimm->dimm_nretired,
		    GMEM_DIMM_STAT_PREFIX);

		gmem_list_append(&gmem.gm_dimms, dimm);
	}

	switch (ptr->ptr_subtype) {
	case GMEM_PTR_DIMM_CASE:
		gmem_mem_case_restore(hdl, &dimm->dimm_case, cp, "dimm",
		    dimm->dimm_serial);
		break;
	default:
		fmd_hdl_abort(hdl, "invalid %s subtype %d\n",
		    ptr->ptr_name, ptr->ptr_subtype);
	}

	return (dimm);
}

void
gmem_dimm_validate(fmd_hdl_t *hdl)
{
	gmem_dimm_t *dimm, *next;

	for (dimm = gmem_list_next(&gmem.gm_dimms); dimm != NULL; dimm = next) {
		next = gmem_list_next(dimm);

		if (!gmem_dimm_present(hdl, dimm->dimm_asru_nvl))
			gmem_dimm_destroy(hdl, dimm);
	}
}

void
gmem_dimm_dirty(fmd_hdl_t *hdl, gmem_dimm_t *dimm)
{
	if (fmd_buf_size(hdl, NULL, dimm->dimm_bufname) !=
	    sizeof (gmem_dimm_pers_t))
		fmd_buf_destroy(hdl, NULL, dimm->dimm_bufname);

	/* No need to rewrite the FMRIs in the dimm - they don't change */
	fmd_buf_write(hdl, NULL, dimm->dimm_bufname, &dimm->dimm_pers,
	    sizeof (gmem_dimm_pers_t));
}

void
gmem_dimm_gc(fmd_hdl_t *hdl)
{
	gmem_dimm_validate(hdl);
}

void
gmem_dimm_fini(fmd_hdl_t *hdl)
{
	gmem_dimm_t *dimm;

	while ((dimm = gmem_list_next(&gmem.gm_dimms)) != NULL)
		gmem_dimm_free(hdl, dimm, FMD_B_FALSE);
}


/*ARGSUSED*/
static int
find_dimm_hc_fmri(topo_hdl_t *thp, tnode_t *node, void *arg)
{

	char *topo_sn;
	dimmid_t *dimmid = (dimmid_t *)arg;
	nvlist_t *fru = NULL;
	nvlist_t *rsc = NULL;
	nvlist_t *asru = NULL;
	int err;

	if (topo_node_fru(node, &fru, NULL, &err) < 0)
		return (TOPO_WALK_NEXT);

	err = nvlist_lookup_string(fru, FM_FMRI_HC_SERIAL_ID, &topo_sn);
	if (err != 0) {
		nvlist_free(fru);
		return (TOPO_WALK_NEXT);
	}

	if (strcmp(dimmid->serial, topo_sn) != 0) {
		nvlist_free(fru);
		return (TOPO_WALK_NEXT);
	}

	switch (dimmid->type) {
		case FINDFRU:
			(void) nvlist_dup(fru, &dimm_nvl, NV_UNIQUE_NAME);
			break;
		case FINDRSC:
			(void) topo_node_resource(node, &rsc, &err);
			if (rsc != NULL) {
				(void) nvlist_dup(rsc, &dimm_nvl,
				    NV_UNIQUE_NAME);
				nvlist_free(rsc);
			}
			break;
		case FINDASRU:
			(void) topo_node_asru(node, &asru, NULL, &err);
			if (asru != NULL) {
				(void) nvlist_dup(asru, &dimm_nvl,
				    NV_UNIQUE_NAME);
				nvlist_free(asru);
			}
			break;
		default:
			break;
	}
	nvlist_free(fru);
	return (TOPO_WALK_TERMINATE);
}

nvlist_t *
gmem_find_dimm_by_sn(fmd_hdl_t *hdl, dimmid_t *dimmid) {
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;
	dimm_nvl = NULL;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (NULL);

	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC,
	    find_dimm_hc_fmri, dimmid, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}

	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
	return (dimm_nvl);
}

nvlist_t *
gmem_find_dimm_fru(fmd_hdl_t *hdl, char *sn)
{
	dimmid_t fru;
	(void) strcpy(fru.serial, sn);
	fru.type = FINDFRU;
	return (gmem_find_dimm_by_sn(hdl, &fru));
}

nvlist_t *
gmem_find_dimm_rsc(fmd_hdl_t *hdl, char *sn)
{
	dimmid_t rsc;
	(void) strcpy(rsc.serial, sn);
	rsc.type = FINDRSC;
	return (gmem_find_dimm_by_sn(hdl, &rsc));
}

nvlist_t *
gmem_find_dimm_asru(fmd_hdl_t *hdl, char *sn)
{
	dimmid_t asru;
	(void) strcpy(asru.serial, sn);
	asru.type = FINDASRU;
	return (gmem_find_dimm_by_sn(hdl, &asru));
}

int
gmem_dimm_present(fmd_hdl_t *hdl, nvlist_t *asru)
{
	char *sn;
	nvlist_t *dimm = NULL;

	if (nvlist_lookup_string(asru, FM_FMRI_HC_SERIAL_ID, &sn) != 0) {
		fmd_hdl_debug(hdl, "Unable to get dimm serial\n");
		return (0);
	}
	dimm = gmem_find_dimm_fru(hdl, sn);
	if (dimm == NULL) {
		fmd_hdl_debug(hdl, "Dimm sn=%s is not present\n", sn);
		return (0);
	}
	nvlist_free(dimm);
	return (1);
}

static int
gmem_find_dimm_chip(nvlist_t *nvl, uint32_t *chip)
{

	char *name, *id, *end;
	nvlist_t **hcl;
	uint_t n;
	int i;
	int rc = 0;
	*chip = ULONG_MAX;

	if (nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcl, &n) < 0)
		return (0);
	for (i = 0; i < n; i++) {
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &name);
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &id);

		if (strcmp(name, "chip") == 0) {
			*chip = (uint32_t)strtoul(id, &end, 10);
			rc = 1;
			break;
		}
	}
	return (rc);
}

/*ARGSUSED*/
int
gmem_same_datapath_dimms(fmd_hdl_t *hdl, gmem_dimm_t *d1, gmem_dimm_t *d2)
{

	if (d1->dimm_chipid == ULONG_MAX || d2->dimm_chipid == ULONG_MAX)
		return (0);

	if (d1->dimm_chipid == d2->dimm_chipid)
		return (1);

	return (0);
}

int
gmem_check_symbol_error(fmd_hdl_t *hdl, gmem_dimm_t *d, uint16_t upos)
{
	gmem_dimm_t *dimm = NULL, *next = NULL;

	for (dimm = gmem_list_next(&gmem.gm_dimms); dimm != NULL;
	    dimm = next) {
		next = gmem_list_next(dimm);
		if (gmem_same_datapath_dimms(hdl, dimm, d) &&
		    dimm->dimm_syl_error == upos)
			return (1);
	}
	return (0);
}

void
gmem_save_symbol_error(fmd_hdl_t *hdl, gmem_dimm_t *d, uint16_t upos)
{
	gmem_dimm_t *dimm = NULL, *next = NULL;

	for (dimm = gmem_list_next(&gmem.gm_dimms); dimm != NULL;
	    dimm = next) {
		next = gmem_list_next(dimm);
		if (gmem_same_datapath_dimms(hdl, dimm, d))
			dimm->dimm_syl_error = upos;
	}
}
