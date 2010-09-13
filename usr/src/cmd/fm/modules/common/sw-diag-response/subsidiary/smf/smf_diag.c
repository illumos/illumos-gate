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
 * SMF software-diagnosis subsidiary
 *
 * We model service instances in maintenance state as a defect diagnosis
 * in FMA.  When an instance transitions to maintenance state the SMF
 * graph engine publishes an event which we subscribe to here, and diagnose
 * a corresponding defect.
 *
 * We always solve a case immediately after opening it.  But we leave the
 * case close action to the response agent which needs to cache case UUIDs.
 * So in the normal case, where software-response is loaded and operational,
 * our cases will transition to CLOSED state moments after we solve them.
 * But if fmd restarts in the interim or if software-response is not loaded
 * then our cases may hang around in SOLVED state for a while, which means
 * we could iterate over them on receipt of new events.  But we don't -
 * we blindly solve a new case for every new maintenance event received,
 * and leave it to the fmd duplicate detection and history-based diagnosis
 * logic to do the right thing.
 *
 * Our sibling SMF response subsidiary propogates fmadm-initiated repairs
 * into SMF, and svcadm-initiated clears back into FMA.  In both cases
 * the case is moved on to the RESOLVED state, even if fmd is unable to
 * verify that the service is out of maintenance state (i.e., no longer
 * isolated).  If the service immediately re-enters maintenance state then
 * we diagnose a fresh case.  The history-based diagnosis changes in fmd
 * "do the right thing" and avoid throwing away new cases as duplicates
 * of old ones hanging around in the "resolved but not all usable again"
 * state.
 */

#include <strings.h>
#include <fm/libtopo.h>
#include <fm/fmd_fmri.h>

#include "../../common/sw.h"
#include "smf.h"

static id_t myid;

static struct {
	fmd_stat_t swde_smf_diagnosed;
	fmd_stat_t swde_smf_bad_class;
	fmd_stat_t swde_smf_no_attr;
	fmd_stat_t swde_smf_bad_attr;
	fmd_stat_t swde_smf_bad_fmri;
	fmd_stat_t swde_smf_no_uuid;
	fmd_stat_t swde_smf_no_reason_short;
	fmd_stat_t swde_smf_no_reason_long;
	fmd_stat_t swde_smf_no_svcname;
	fmd_stat_t swde_smf_admin_maint_drop;
	fmd_stat_t swde_smf_bad_nvlist_pack;
	fmd_stat_t swde_smf_dupuuid;
} swde_smf_stats = {
	{ "swde_smf_diagnosed", FMD_TYPE_UINT64,
	    "maintenance state defects published" },
	{ "swde_smf_bad_class", FMD_TYPE_UINT64,
	    "incorrect event class received" },
	{ "swde_smf_no_attr", FMD_TYPE_UINT64,
	    "malformed event - missing attr nvlist" },
	{ "swde_smf_bad_attr", FMD_TYPE_UINT64,
	    "malformed event - invalid attr list" },
	{ "swde_smf_bad_fmri", FMD_TYPE_UINT64,
	    "malformed event - fmri2str fails" },
	{ "swde_smf_no_uuid", FMD_TYPE_UINT64,
	    "malformed event - missing uuid" },
	{ "swde_smf_no_reason_short", FMD_TYPE_UINT64,
	    "SMF transition event had no reason-short" },
	{ "swde_smf_no_reason_long", FMD_TYPE_UINT64,
	    "SMF transition event had no reason-long" },
	{ "swde_smf_no_svcname", FMD_TYPE_UINT64,
	    "SMF transition event had no svc-string" },
	{ "swde_smf_admin_maint_drop", FMD_TYPE_UINT64,
	    "maintenance transitions requested by admin - no diagnosis" },
	{ "swde_smf_bad_nvlist_pack", FMD_TYPE_UINT64,
	    "failed nvlist_size or nvlist_pack" },
	{ "swde_smf_dupuuid", FMD_TYPE_UINT64,
	    "duplicate events received" },
};

#define	SWDE_SMF_CASEDATA_VERS		1

typedef struct swde_smf_casedata {
	uint32_t scd_vers;		/* must be first member */
	size_t scd_nvlbufsz;		/* size of following buffer */
					/* packed fmri nvlist follows */
} swde_smf_casedata_t;

#define	BUMPSTAT(stat)		swde_smf_stats.stat.fmds_value.ui64++

/*ARGSUSED*/
void
swde_smf_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, void *arg)
{
	char *rsn = NULL, *rsnl = NULL, *svcname = NULL;
	nvlist_t *attr, *svcfmri, *defect;
	swde_smf_casedata_t *cdp;
	fmd_case_t *cp;
	char *fmribuf;
	char *uuid;
	size_t sz;

	if (!fmd_nvl_class_match(hdl, nvl, TRANCLASS("maintenance"))) {
		BUMPSTAT(swde_smf_bad_class);
		return;
	}

	if (nvlist_lookup_nvlist(nvl, FM_IREPORT_ATTRIBUTES, &attr) != 0) {
		BUMPSTAT(swde_smf_no_attr);
		return;
	}

	if (nvlist_lookup_string(nvl, FM_IREPORT_UUID, &uuid) != 0) {
		BUMPSTAT(swde_smf_no_uuid);
		return;
	}

	if (nvlist_lookup_nvlist(attr, "svc", &svcfmri) != 0) {
		BUMPSTAT(swde_smf_bad_attr);
		return;
	}

	if (nvlist_lookup_string(attr, "reason-short", &rsn) != 0) {
		BUMPSTAT(swde_smf_no_reason_short);
		return;
	}

	if (nvlist_lookup_string(attr, "reason-long", &rsnl) != 0) {
		BUMPSTAT(swde_smf_no_reason_long);
		return;
	}

	if (nvlist_lookup_string(attr, "svc-string", &svcname) != 0) {
		BUMPSTAT(swde_smf_no_svcname);
		return;
	}

	if (strcmp(rsn, "administrative_request") == 0) {
		BUMPSTAT(swde_smf_admin_maint_drop);
		return;
	}

	/*
	 * Our case checkpoint data, version 1.
	 */
	if (nvlist_size(svcfmri, &sz, NV_ENCODE_NATIVE) != 0) {
		BUMPSTAT(swde_smf_bad_nvlist_pack);
		return;
	}
	cdp = fmd_hdl_zalloc(hdl, sizeof (*cdp) + sz, FMD_SLEEP);
	cdp->scd_vers = SWDE_SMF_CASEDATA_VERS;
	fmribuf = (char *)cdp + sizeof (*cdp);
	cdp->scd_nvlbufsz = sz;
	(void) nvlist_pack(svcfmri, &fmribuf, &sz, NV_ENCODE_NATIVE, 0);

	/*
	 * Open a case with UUID matching the originating event, and no
	 * associated serialization data.  Create a defect and add it to
	 * the case, and link the originating event to the case.  This
	 * call will return NULL if a case with the requested UUID already
	 * exists, which would mean we are processing an event twice so
	 * we can discard.
	 */
	if ((cp = swde_case_open(hdl, myid, uuid, SWDE_SMF_CASEDATA_VERS,
	    (void *)cdp, sizeof (*cdp) + sz)) == NULL) {
		BUMPSTAT(swde_smf_dupuuid);
		fmd_hdl_free(hdl, cdp, sizeof (*cdp) + sz);
		return;
	}

	defect = fmd_nvl_create_defect(hdl, SW_SMF_MAINT_DEFECT,
	    100, svcfmri, NULL, svcfmri);
	if (rsn != NULL)
		(void) nvlist_add_string(defect, "reason-short", rsn);
	if (rsnl != NULL)
		(void) nvlist_add_string(defect, "reason-long", rsnl);
	if (svcname != NULL)
		(void) nvlist_add_string(defect, "svc-string", svcname);
	fmd_case_add_suspect(hdl, cp, defect);
	fmd_case_add_ereport(hdl, cp, ep);

	/*
	 * Now solve the case, and immediately close it.  Although the
	 * resource is already isolated (SMF put it in maintenance state)
	 * we do not immediately close the case here - our sibling response
	 * logic will do that after caching the case UUID.
	 */
	fmd_case_solve(hdl, cp);
	BUMPSTAT(swde_smf_diagnosed);
}

/*
 * In the normal course of events we keep in sync with SMF through the
 * maintenance enter/clear events it raises.  Even if a maintenance
 * state is cleared using svcadm while fmd is not running, the event
 * will pend and be consumed when fmd does start and we'll close the
 * case (in the response agent).
 *
 * But is is possible for discontinuities to produce some confusion:
 *
 *	- if an instance is in maintenance state (and so shown in svcs -x
 *	  and fmadm faulty output) at the time we clone a new boot
 *	  environment then when we boot the new BE we can be out of
 *	  sync if the instance is cleared when we boot there
 *
 *	- meddling with /var/fm state - eg manual clear of files there,
 *	  or restore of old state
 *
 * So as an extra guard we have a case verify function which is called
 * at fmd restart (module load for software-diagnosis).  We must
 * return 0 to close the case, non-zero to retain it.
 */
int
swde_smf_vrfy(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	swde_smf_casedata_t *cdp;
	nvlist_t *svcfmri;
	uint32_t v;
	int rv;

	cdp = swde_case_data(hdl, cp, &v);

	if (cdp == NULL || v != 1)
		return (0);	/* bad or damaged - just close */

	if (nvlist_unpack((char *)cdp + sizeof (*cdp),
	    cdp->scd_nvlbufsz, &svcfmri, 0) != 0)
		return (0);	/* ditto */

	switch (fmd_nvl_fmri_service_state(hdl, svcfmri)) {
	case FMD_SERVICE_STATE_UNUSABLE:
		/*
		 * Keep case iff in maintenance state
		 */
		rv = 1;
		break;

	default:
		/*
		 * Discard the case for all other states - cleared,
		 * service no longer exists, ... whatever.
		 */
		rv = 0;
		break;
	}

	nvlist_free(svcfmri);
	return (rv);
}

const struct sw_disp swde_smf_disp[] = {
	{ TRANCLASS("maintenance"), swde_smf_recv, NULL },
	{ NULL, NULL, NULL }
};

/*ARGSUSED*/
int
swde_smf_init(fmd_hdl_t *hdl, id_t id, const struct sw_disp **dpp, int *nelemp)
{
	myid = id;

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (swde_smf_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&swde_smf_stats);

	fmd_hdl_subscribe(hdl, TRANCLASS("maintenance"));

	*dpp = &swde_smf_disp[0];
	*nelemp = sizeof (swde_smf_disp) / sizeof (swde_smf_disp[0]);
	return (SW_SUB_INIT_SUCCESS);
}

const struct sw_subinfo smf_diag_info = {
	"smf diagnosis",		/* swsub_name */
	SW_CASE_SMF,			/* swsub_casetype */
	swde_smf_init,			/* swsub_init */
	NULL,				/* swsub_fini */
	NULL,				/* swsub_timeout */
	NULL,				/* swsub_case_close */
	swde_smf_vrfy,			/* swsub_case_vrfy */
};
