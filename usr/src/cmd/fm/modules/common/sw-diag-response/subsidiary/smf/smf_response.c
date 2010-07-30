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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * SMF software-response subsidiary
 */

#include <strings.h>
#include <fm/libtopo.h>
#include <libscf.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_fmri.h>

#include "../../common/sw.h"
#include "smf.h"

static struct {
	fmd_stat_t swrp_smf_repairs;
	fmd_stat_t swrp_smf_clears;
	fmd_stat_t swrp_smf_closed;
	fmd_stat_t swrp_smf_wrongclass;
	fmd_stat_t swrp_smf_badlist;
	fmd_stat_t swrp_smf_badresource;
	fmd_stat_t swrp_smf_badclrevent;
	fmd_stat_t swrp_smf_noloop;
	fmd_stat_t swrp_smf_suppressed;
	fmd_stat_t swrp_smf_cachefull;
} swrp_smf_stats = {
	{ "swrp_smf_repairs", FMD_TYPE_UINT64,
	    "repair events received for propogation to SMF" },
	{ "swrp_smf_clears", FMD_TYPE_UINT64,
	    "notifications from SMF of exiting maint state" },
	{ "swrp_smf_closed", FMD_TYPE_UINT64,
	    "cases closed" },
	{ "swrp_smf_wrongclass", FMD_TYPE_UINT64,
	    "unexpected event class received" },
	{ "swrp_smf_badlist", FMD_TYPE_UINT64,
	    "list event with invalid structure" },
	{ "swrp_smf_badresource", FMD_TYPE_UINT64,
	    "list.repaired with smf fault but bad svc fmri" },
	{ "swrp_smf_badclrevent", FMD_TYPE_UINT64,
	    "maint clear event from SMF malformed" },
	{ "swrp_smf_noloop", FMD_TYPE_UINT64,
	    "avoidance of smf->fmd->smf repairs propogations" },
	{ "swrp_smf_suppressed", FMD_TYPE_UINT64,
	    "not propogated to smf because no longer in maint" },
	{ "swrp_smf_cachefull", FMD_TYPE_UINT64,
	    "uuid cache full" },
};

#define	BUMPSTAT(stat)		swrp_smf_stats.stat.fmds_value.ui64++

#define	CACHE_NENT_INC		16
#define	CACHE_NENT_MAX		128

struct smf_uuid_cache_ent {
	char uuid[37];
	char fmristr[90];
	uint8_t mark;
};

#define	CACHE_VERSION		1

struct smf_uuid_cache {
	uint32_t version;			/* Version */
	uint32_t nentries;			/* Real size of array below */
	struct smf_uuid_cache_ent entry[1];	/* Cache entries */
};

static struct smf_uuid_cache *uuid_cache;

#define	UUID_CACHE_BUFNAME	"uuid_cache"

static void
uuid_cache_grow(fmd_hdl_t *hdl)
{
	struct smf_uuid_cache *newcache;
	size_t newsz;
	uint32_t n;

	n = (uuid_cache == NULL ? 0 : uuid_cache->nentries) + CACHE_NENT_INC;
	newsz = sizeof (struct smf_uuid_cache) + (n - 1) *
	    sizeof (struct smf_uuid_cache_ent);

	newcache = fmd_hdl_zalloc(hdl, newsz, FMD_SLEEP);
	newcache->version = CACHE_VERSION;
	newcache->nentries = n;

	if (uuid_cache != NULL) {
		uint32_t oldn = uuid_cache->nentries;
		size_t oldsz = sizeof (struct smf_uuid_cache) +
		    (oldn - 1) * sizeof (struct smf_uuid_cache_ent);

		bcopy(&uuid_cache->entry[0], &newcache->entry[0], oldsz);
		fmd_hdl_free(hdl, uuid_cache, oldsz);
		fmd_buf_destroy(hdl, NULL, UUID_CACHE_BUFNAME);
	}

	uuid_cache = newcache;
	fmd_buf_create(hdl, NULL, UUID_CACHE_BUFNAME, newsz);
}

static void
uuid_cache_persist(fmd_hdl_t *hdl)
{
	size_t sz = sizeof (struct smf_uuid_cache) +
	    (uuid_cache->nentries - 1) * sizeof (struct smf_uuid_cache_ent);

	fmd_buf_write(hdl, NULL, UUID_CACHE_BUFNAME, uuid_cache, sz);
}

/*
 * Garbage-collect the uuid cache.  Any cases that are already resolved
 * we do not need an entry for.  If a case is not resolved but the
 * service involved in that case is no longer in maintenance state
 * then we've lost sync somehow, so repair the asru (which will
 * also resolve the case).
 */
static void
uuid_cache_gc(fmd_hdl_t *hdl)
{
	struct smf_uuid_cache_ent *entp;
	topo_hdl_t *thp = NULL;
	nvlist_t *svcfmri;
	char *svcname;
	int err, i;

	for (i = 0; i < uuid_cache->nentries; i++) {
		entp = &uuid_cache->entry[i];

		if (entp->uuid[0] == '\0')
			continue;

		if (fmd_case_uuisresolved(hdl, entp->uuid)) {
			bzero(entp->uuid, sizeof (entp->uuid));
			bzero(entp->fmristr, sizeof (entp->fmristr));
			entp->mark = 0;
		} else {
			if (thp == NULL)
				thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION);

			if (topo_fmri_str2nvl(thp, entp->fmristr, &svcfmri,
			    &err) != 0) {
				fmd_hdl_error(hdl, "str2nvl failed for %s\n",
				    entp->fmristr);
				continue;
			}

			if (fmd_nvl_fmri_service_state(hdl, svcfmri) !=
			    FMD_SERVICE_STATE_UNUSABLE) {
				svcname = sw_smf_svcfmri2shortstr(hdl, svcfmri);
				(void) fmd_repair_asru(hdl, entp->fmristr);
				fmd_hdl_strfree(hdl, svcname);
			}

			nvlist_free(svcfmri);
		}
	}

	if (thp)
		fmd_hdl_topo_rele(hdl, thp);

	uuid_cache_persist(hdl);
}

static void
uuid_cache_restore(fmd_hdl_t *hdl)
{
	size_t sz = fmd_buf_size(hdl, NULL, UUID_CACHE_BUFNAME);

	if (sz == 0)
		return;

	uuid_cache = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	fmd_buf_read(hdl, NULL, UUID_CACHE_BUFNAME, uuid_cache, sz);

	/*
	 * Garbage collect now, not just for tidiness but also to help
	 * fmd and smf state stay in sync at module startup.
	 */
	uuid_cache_gc(hdl);
}

/*
 * Add the UUID of an SMF maintenance defect case to our cache and
 * record the associated full svc FMRI string for the case.
 */
static void
swrp_smf_cache_add(fmd_hdl_t *hdl, char *uuid, char *fmristr)
{
	struct smf_uuid_cache_ent *entp = NULL;
	int gced = 0;
	int i;

	if (uuid_cache == NULL)
		uuid_cache_grow(hdl);

	/*
	 * If we somehow already have an entry for this uuid then
	 * return leaving it undisturbed.
	 */
	for (i = 0; i < uuid_cache->nentries; i++) {
		if (strcmp(uuid, uuid_cache->entry[i].uuid) == 0)
			return;
	}

scan:
	for (i = 0; i < uuid_cache->nentries; i++) {
		if (uuid_cache->entry[i].uuid[0] == '\0') {
			entp = &uuid_cache->entry[i];
			break;
		}
	}

	if (entp == NULL) {
		uint32_t oldn = uuid_cache->nentries;

		/*
		 * Before growing the cache we try again after first
		 * garbage-collecting the existing cache for any cases
		 * that are confirmed as resolved.
		 */
		if (!gced) {
			uuid_cache_gc(hdl);
			gced = 1;
			goto scan;
		}

		if (oldn < CACHE_NENT_MAX) {
			uuid_cache_grow(hdl);
			entp = &uuid_cache->entry[oldn];
		} else {
			BUMPSTAT(swrp_smf_cachefull);
			return;
		}
	}

	(void) strncpy(entp->uuid, uuid, sizeof (entp->uuid));
	(void) strncpy(entp->fmristr, fmristr, sizeof (entp->fmristr));
	uuid_cache_persist(hdl);
}

/*
 * Mark cache entry/entries as resolved - if they match in either uuid
 * (if not NULL) or fmristr (if not NULL) mark as resolved.  Return 1 iff
 * an entry that matched on uuid was already marked, otherwise (entry
 * matched on either, matched on uuid but not marked, not found).
 */
static int
swrp_smf_cache_mark(fmd_hdl_t *hdl, char *uuid, char *fmristr)
{
	int dirty = 0;
	int rv = 0;
	int i;

	if (uuid_cache == NULL)
		return (0);

	for (i = 0; i < uuid_cache->nentries; i++) {
		struct smf_uuid_cache_ent *entp = &uuid_cache->entry[i];

		if (entp->uuid[0] == '\0')
			continue;

		if (uuid && strcmp(uuid, entp->uuid) == 0) {
			if (entp->mark)
				rv = 1;
			entp->mark = 1;
			dirty++;
		} else if (fmristr && strcmp(fmristr, entp->fmristr) == 0) {
			entp->mark = 1;
			dirty++;
		}
	}

	if (dirty)
		uuid_cache_persist(hdl);

	return (rv);
}

/*
 * We will receive list events for cases we are not interested in.  Test
 * that this list has exactly one suspect and that it matches the maintenance
 * defect.  Return the defect to the caller in the second argument,
 * and the defect resource element in the third arg.
 */
static int
suspect_is_maint_defect(fmd_hdl_t *hdl, nvlist_t *nvl,
    nvlist_t **defectnvl, nvlist_t **rsrcnvl)
{
	nvlist_t **faults;
	uint_t nfaults;

	if (nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &faults, &nfaults) != 0) {
		BUMPSTAT(swrp_smf_badlist);
		return (0);
	}

	if (nfaults != 1 ||
	    !fmd_nvl_class_match(hdl, faults[0], SW_SMF_MAINT_DEFECT))
		return (0);

	if (nvlist_lookup_nvlist(faults[0], FM_FAULT_RESOURCE, rsrcnvl) != 0) {
		BUMPSTAT(swrp_smf_badlist);
		return (0);
	}

	*defectnvl = faults[0];

	return (1);
}

/*
 * Received newly-diagnosed list.suspect events that are for the
 * maintenane defect we diagnose.  Close the case (the resource was already
 * isolated by SMF) after cachng the case UUID.
 */
/*ARGSUSED*/
static void
swrp_smf_cacheuuid(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, void *arg)
{
	nvlist_t *defect, *rsrc;
	char *fmristr, *uuid;

	if (nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) != 0) {
		BUMPSTAT(swrp_smf_badlist);
		return;
	}

	if (!suspect_is_maint_defect(hdl, nvl, &defect, &rsrc))
		return;

	if ((fmristr = sw_smf_svcfmri2str(hdl, rsrc)) == NULL) {
		BUMPSTAT(swrp_smf_badlist);
		return;
	}

	swrp_smf_cache_add(hdl, uuid, fmristr);
	fmd_hdl_strfree(hdl, fmristr);

	if (!fmd_case_uuclosed(hdl, uuid)) {
		fmd_case_uuclose(hdl, uuid);
		BUMPSTAT(swrp_smf_closed);
	}
}

/*ARGSUSED*/
static void
swrp_smf2fmd(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, void *arg)
{
	nvlist_t *attr, *fmri;
	char *fromstate;
	char *fmristr;

	if (!fmd_nvl_class_match(hdl, nvl, TRANCLASS("*"))) {
		BUMPSTAT(swrp_smf_wrongclass);
		return;
	}

	if (nvlist_lookup_nvlist(nvl, FM_IREPORT_ATTRIBUTES, &attr) != 0 ||
	    nvlist_lookup_string(attr, "from-state", &fromstate) != 0) {
		BUMPSTAT(swrp_smf_badclrevent);
		return;
	}

	/*
	 * Filter those not describing a transition out of maintenance.
	 */
	if (strcmp(fromstate, "maintenance") != 0)
		return;

	if (nvlist_lookup_nvlist(attr, "svc", &fmri) != 0) {
		BUMPSTAT(swrp_smf_badclrevent);
		return;
	}

	if ((fmristr = sw_smf_svcfmri2str(hdl, fmri)) == NULL) {
		BUMPSTAT(swrp_smf_badclrevent);
		return;
	}

	/*
	 * Mark any UUID for a case against this service as resolved
	 * in our cache.  When we fmd_repair_asru below fmd will emit
	 * a list.repaired as a result, and our handling of that event
	 * must not propogate the repair towards SMF (since the repair
	 * was initiated via SMF itself and not via fmadm).
	 */
	(void) swrp_smf_cache_mark(hdl, NULL, fmristr);

	(void) fmd_repair_asru(hdl, fmristr);
	fmd_hdl_strfree(hdl, fmristr);
	BUMPSTAT(swrp_smf_clears);
}

/*ARGSUSED*/
static void
swrp_fmd2smf(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, void *arg)
{
	char *fmristr, *shrtfmristr;
	nvlist_t *defect, *rsrc;
	char *uuid;
	int already;

	if (strcmp(class, FM_LIST_REPAIRED_CLASS) != 0) {
		BUMPSTAT(swrp_smf_wrongclass);
		return;
	}

	if (nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid) != 0) {
		BUMPSTAT(swrp_smf_badlist);
		return;
	}

	if (!suspect_is_maint_defect(hdl, nvl, &defect, &rsrc))
		return;

	if ((fmristr = sw_smf_svcfmri2str(hdl, rsrc)) == NULL) {
		BUMPSTAT(swrp_smf_badresource);
		return;
	}

	already = swrp_smf_cache_mark(hdl, uuid, fmristr);
	fmd_hdl_strfree(hdl, fmristr);

	/*
	 * If the cache already had a marked entry for this UUID then
	 * this is a list.repaired arising from a SMF-initiated maintenance
	 * clear (propogated with fmd_repair_asru above which then results
	 * in a list.repaired) and so we should not propogate the repair
	 * back towards SMF.  But do still force the case to RESOLVED state in
	 * case fmd is unable to confirm the service no longer in maintenance
	 * state (it may have failed again) so that a new case can be opened.
	 */
	fmd_case_uuresolved(hdl, uuid);
	if (already) {
		BUMPSTAT(swrp_smf_noloop);
		return;
	}

	/*
	 * Only propogate to SMF if we can see that service still
	 * in maintenance state.  We're not synchronized with SMF
	 * and this state could change at any time, but if we can
	 * see it's not in maintenance state then things are obviously
	 * moving (e.g., external svcadm active) so we don't poke
	 * at SMF otherwise we confuse things or duplicate operations.
	 */

	if (fmd_nvl_fmri_service_state(hdl, rsrc) ==
	    FMD_SERVICE_STATE_UNUSABLE) {
		shrtfmristr = sw_smf_svcfmri2shortstr(hdl, rsrc);

		if (shrtfmristr != NULL) {
			(void) smf_restore_instance(shrtfmristr);
			fmd_hdl_strfree(hdl, shrtfmristr);
			BUMPSTAT(swrp_smf_repairs);
		} else {
			BUMPSTAT(swrp_smf_badresource);
		}
	} else {
		BUMPSTAT(swrp_smf_suppressed);
	}
}

const struct sw_disp swrp_smf_disp[] = {
	{ TRANCLASS("*"), swrp_smf2fmd, NULL },
	{ FM_LIST_SUSPECT_CLASS, swrp_smf_cacheuuid, NULL },
	{ FM_LIST_REPAIRED_CLASS, swrp_fmd2smf, NULL },
	{ NULL, NULL, NULL }
};

/*ARGSUSED*/
int
swrp_smf_init(fmd_hdl_t *hdl, id_t id, const struct sw_disp **dpp, int *nelemp)
{
	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (swrp_smf_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&swrp_smf_stats);

	uuid_cache_restore(hdl);

	/*
	 * We need to subscribe to all SMF transition class events because
	 * we need to look inside the payload to see which events indicate
	 * a transition out of maintenance state.
	 */
	fmd_hdl_subscribe(hdl, TRANCLASS("*"));

	/*
	 * Subscribe to the defect class diagnosed for maintenance events.
	 * The module will then receive list.suspect events including
	 * these defects, and in our dispatch table above we list routing
	 * for list.suspect.
	 */
	fmd_hdl_subscribe(hdl, SW_SMF_MAINT_DEFECT);

	*dpp = &swrp_smf_disp[0];
	*nelemp = sizeof (swrp_smf_disp) / sizeof (swrp_smf_disp[0]);
	return (SW_SUB_INIT_SUCCESS);
}

/*ARGSUSED*/
void
swrp_smf_fini(fmd_hdl_t *hdl)
{
}

const struct sw_subinfo smf_response_info = {
	"smf repair",			/* swsub_name */
	SW_CASE_NONE,			/* swsub_casetype */
	swrp_smf_init,			/* swsub_init */
	swrp_smf_fini,			/* swsub_fini */
	NULL,				/* swsub_timeout */
	NULL,				/* swsub_case_close */
	NULL,				/* swsub_case_vrfy */
};
