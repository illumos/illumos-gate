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
 * Panic software-diagnosis subsidiary
 *
 * We model a system panic as a defect diagnosis in FMA. When a system
 * panicks, savecore publishes events which we subscribe to here.
 *
 * Our driving events are all raised by savecore, run either from
 * startup of the dumpadm service or interactively at the command line.
 * The following describes the logic for the handling of these events.
 *
 * On reboot after panic we will run savecore as part of the dumpadm
 * service startup; we run savecore even if savecore is otherwise
 * disabled (ie dumpadm -n in effect) - we run savecore -c to check for
 * a valid dump and raise the initial event.
 *
 * If savecore (or savecore -c) observes a valid dump pending on the
 * device, it raises a "dump_pending_on_device" event provided this
 * was not an FMA-initiated panic (for those we will replay ereports
 * from the dump device as usual and make a diagnosis from those; we do
 * not need to open a case for the panic).  We subscribe to the
 * "dump_pending_on_device" event and use that to open a case;  we
 * open a case requesting the same case uuid as the panic dump image
 * has for the OS instance uuid - if that fails because of a duplicate
 * uuid then we have already opened a case for this panic so no need
 * to open another.
 *
 * Included in the "dump_pending_on_device" event is an indication of
 * whether or not dumpadm is enabled.  If not (dumpadm -n in effect)
 * then we do not expect any further events regarding this panic
 * until such time as the admin runs savecore manually (if ever).
 * So in this case we solve the case immediately after open.  If/when
 * subsequent events arrive when savecore is run manually, we will toss
 * them.
 *
 * If dumpadm is enabled then savecore, run from dumpadm service startup,
 * will attempt to process the dump - either to copy it off the dump
 * device (if saving compressed) or to uncompress it off the dump device.
 * If this succeeds savecore raises a "dump_available" event which
 * includes information on the directory it was saved in, the instance
 * number, image uuid, compressed form or not, and whether the dump
 * was complete (as per the dumphdr).  If the savecore fails for
 * some reason then it exits and raises a "savecore_failure" event.
 * These two events are raised even for FMA-initiated panics.
 *
 * We subscribe to both the "dump_available" and "savecore_failed" events,
 * and in the handling thereof we will close the case opened earlier (if
 * this is not an FMA-initiated panic).  On receipt of the initial
 * "dump_available" event we also arm a timer for +10 minutes if
 * dumpadm is enabled - if no "dump_available" or "savecore_failed" arrives
 * in that time we will solve the case on timeout.
 *
 * When the timer fires we check whether the initial event for each panic
 * case was received more than 30 minutes ago; if it was we solve the case
 * with what we have.  If we're still within the waiting period we rearm
 * for a further 10 minutes.  The timer is shared by all cases that we
 * create, which is why the fire interval is shorter than the maximum time
 * we are prepared to wait.
 */

#include <strings.h>
#include <sys/panic.h>
#include <alloca.h>
#include <zone.h>

#include "../../common/sw.h"
#include "panic.h"

#define	MAX_STRING_LEN 160

static id_t myid;

static id_t mytimerid;

/*
 * Our serialization structure type.
 */
#define	SWDE_PANIC_CASEDATA_VERS	1

typedef struct swde_panic_casedata {
	uint32_t scd_vers;		/* must be first member */
	uint64_t scd_receive_time;	/* when we first knew of this panic */
	size_t scd_nvlbufsz;		/* size of following buffer */
					/* packed attr nvlist follows */
} swde_panic_casedata_t;

static struct {
	fmd_stat_t swde_panic_diagnosed;
	fmd_stat_t swde_panic_badclass;
	fmd_stat_t swde_panic_noattr;
	fmd_stat_t swde_panic_unexpected_fm_panic;
	fmd_stat_t swde_panic_badattr;
	fmd_stat_t swde_panic_badfmri;
	fmd_stat_t swde_panic_noinstance;
	fmd_stat_t swde_panic_nouuid;
	fmd_stat_t swde_panic_dupuuid;
	fmd_stat_t swde_panic_nocase;
	fmd_stat_t swde_panic_notime;
	fmd_stat_t swde_panic_nopanicstr;
	fmd_stat_t swde_panic_nodumpdir;
	fmd_stat_t swde_panic_nostack;
	fmd_stat_t swde_panic_incomplete;
	fmd_stat_t swde_panic_failed;
	fmd_stat_t swde_panic_basecasedata;
	fmd_stat_t swde_panic_failsrlz;
} swde_panic_stats = {
	{ "swde_panic_diagnosed", FMD_TYPE_UINT64,
	    "panic defects published" },
	{ "swde_panic_badclass", FMD_TYPE_UINT64,
	    "incorrect event class received" },
	{ "swde_panic_noattr", FMD_TYPE_UINT64,
	    "malformed event - missing attr nvlist" },
	{ "swde_panic_unexpected_fm_panic", FMD_TYPE_UINT64,
	    "dump available for an fm_panic()" },
	{ "swde_panic_badattr", FMD_TYPE_UINT64,
	    "malformed event - invalid attr list" },
	{ "swde_panic_badfmri", FMD_TYPE_UINT64,
	    "malformed event - fmri2str fails" },
	{ "swde_panic_noinstance", FMD_TYPE_UINT64,
	    "malformed event - no instance number" },
	{ "swde_panic_nouuid", FMD_TYPE_UINT64,
	    "malformed event - missing uuid" },
	{ "swde_panic_dupuuid", FMD_TYPE_UINT64,
	    "duplicate events received" },
	{ "swde_panic_nocase", FMD_TYPE_UINT64,
	    "case missing for uuid" },
	{ "swde_panic_notime", FMD_TYPE_UINT64,
	    "missing crash dump time" },
	{ "swde_panic_nopanicstr", FMD_TYPE_UINT64,
	    "missing panic string" },
	{ "swde_panic_nodumpdir", FMD_TYPE_UINT64,
	    "missing crashdump save directory" },
	{ "swde_panic_nostack", FMD_TYPE_UINT64,
	    "missing panic stack" },
	{ "swde_panic_incomplete", FMD_TYPE_UINT64,
	    "missing panic incomplete" },
	{ "swde_panic_failed", FMD_TYPE_UINT64,
	    "missing panic failed" },
	{ "swde_panic_badcasedata", FMD_TYPE_UINT64,
	    "bad case data during timeout" },
	{ "swde_panic_failsrlz", FMD_TYPE_UINT64,
	    "failures to serialize case data" },
};

#define	BUMPSTAT(stat)		swde_panic_stats.stat.fmds_value.ui64++

static nvlist_t *
panic_sw_fmri(fmd_hdl_t *hdl, char *object)
{
	nvlist_t *fmri;
	nvlist_t *sw_obj;
	int err = 0;

	fmri = fmd_nvl_alloc(hdl, FMD_SLEEP);
	err |= nvlist_add_uint8(fmri, FM_VERSION, FM_SW_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_SW);

	sw_obj = fmd_nvl_alloc(hdl, FMD_SLEEP);
	err |= nvlist_add_string(sw_obj, FM_FMRI_SW_OBJ_PATH, object);
	err |= nvlist_add_nvlist(fmri, FM_FMRI_SW_OBJ, sw_obj);
	nvlist_free(sw_obj);
	if (!err)
		return (fmri);
	else
		return (0);
}

static const char *dumpfiles[2] = { "unix.%lld", "vmcore.%lld" };
static const char *dumpfiles_comp[2] = { "vmdump.%lld", NULL};

static void
swde_panic_solve(fmd_hdl_t *hdl, fmd_case_t *cp,
    nvlist_t *attr, fmd_event_t *ep, boolean_t savecore_success)
{
	char *dumpdir, *path, *uuid;
	nvlist_t *defect, *rsrc;
	nvpair_t *nvp;
	int i;

	/*
	 * Attribute members to include in event-specific defect
	 * payload.  Some attributes will not be present for some
	 * cases - e.g., if we timed out and solved the case without
	 * a "dump_available" report.
	 */
	const char *toadd[] = {
		"os-instance-uuid",	/* same as case uuid */
		"panicstr",		/* for initial classification work */
		"panicstack",		/* for initial classification work */
		"crashtime",		/* in epoch time */
		"panic-time",		/* Formatted crash time */
	};

	if (ep != NULL)
		fmd_case_add_ereport(hdl, cp, ep);
	/*
	 * As a temporary solution we create and fmri in the sw scheme
	 * in panic_sw_fmri. This should become a generic fmri constructor
	 *
	 * We need to user a resource FMRI which will have a sufficiently
	 * unique string representation such that fmd will not see
	 * repeated panic diagnoses (all using the same defect class)
	 * as duplicates and discard later cases.  We can't actually diagnose
	 * the panic to anything specific (e.g., a path to a module and
	 * function/line etc therein).  We could pick on a generic
	 * representative such as /kernel/genunix but that could lead
	 * to misunderstanding.  So we choose a path based on <dumpdir>
	 * and the OS instance UUID - "<dumpdir>/.<os-instance-uuid>".
	 * There's no file at that path (*) but no matter.  We can't use
	 * <dumpdir>/vmdump.N or similar because if savecore is disabled
	 * or failed we don't have any file or instance number.
	 *
	 * (*) Some day it would seem tidier to keep all files to do
	 * with a single crash (unix/vmcore/vmdump, analysis output etc)
	 * in a distinct directory, and <dumpdir>/.<uuid> seems like a good
	 * choice.  For compatability we'd symlink into it.  So that is
	 * another reason for this choice - some day it may exist!
	 */
	(void) nvlist_lookup_string(attr, "dumpdir", &dumpdir);
	(void) nvlist_lookup_string(attr, "os-instance-uuid", &uuid);
	path = alloca(strlen(dumpdir) + 1 + 1 + 36 + 1);
	/* LINTED: E_SEC_SPRINTF_UNBOUNDED_COPY */
	(void) sprintf(path, "%s/.%s", dumpdir, uuid);
	rsrc = panic_sw_fmri(hdl, path);

	defect = fmd_nvl_create_defect(hdl, SW_SUNOS_PANIC_DEFECT,
	    100, rsrc, NULL, rsrc);
	nvlist_free(rsrc);

	(void) nvlist_add_boolean_value(defect, "savecore-succcess",
	    savecore_success);

	if (savecore_success) {
		boolean_t compressed;
		int64_t instance;
		const char **pathfmts;
		char buf[2][32];
		int files = 0;
		char *arr[2];
		int i;

		(void) nvlist_lookup_int64(attr, "instance", &instance);
		(void) nvlist_lookup_boolean_value(attr, "compressed",
		    &compressed);

		pathfmts = compressed ? &dumpfiles_comp[0] : &dumpfiles[0];

		for (i = 0; i < 2; i++) {
			if (pathfmts[i] == NULL) {
				arr[i] = NULL;
				continue;
			}

			(void) snprintf(buf[i], 32, pathfmts[i], instance);
			arr[i] = buf[i];
			files++;
		}

		(void) nvlist_add_string(defect, "dump-dir", dumpdir);
		(void) nvlist_add_string_array(defect, "dump-files", arr,
		    files);
	} else {
		char *rsn;

		if (nvlist_lookup_string(attr, "failure-reason", &rsn) == 0)
			(void) nvlist_add_string(defect, "failure-reason", rsn);
	}

	/*
	 * Not all attributes will necessarily be available - eg if
	 * dumpadm was not enabled there'll be no instance and dumpdir.
	 */
	for (i = 0; i < sizeof (toadd) / sizeof (toadd[0]); i++) {
		if (nvlist_lookup_nvpair(attr, toadd[i], &nvp) == 0)
			(void) nvlist_add_nvpair(defect, nvp);
	}

	fmd_case_add_suspect(hdl, cp, defect);
	fmd_case_solve(hdl, cp);

	/*
	 * Close the case.  Do no free casedata - framework does that for us
	 * on closure callback.
	 */
	fmd_case_close(hdl, cp);
	BUMPSTAT(swde_panic_diagnosed);
}

/*ARGSUSED*/
static void
swde_panic_timeout(fmd_hdl_t *hdl, id_t timerid, void *data)
{
	fmd_case_t *cp = swde_case_first(hdl, myid);
	swde_panic_casedata_t *cdp;
	time_t now = time(NULL);
	nvlist_t *attr;
	int remain = 0;
	uint32_t vers;

	while (cp != NULL) {
		cdp = swde_case_data(hdl, cp, &vers);
		if (vers != SWDE_PANIC_CASEDATA_VERS)
			fmd_hdl_abort(hdl, "case data version confused\n");

		if (now > cdp->scd_receive_time + 30 * 60) {
			if (nvlist_unpack((char *)cdp + sizeof (*cdp),
			    cdp->scd_nvlbufsz, &attr, 0) == 0) {
				swde_panic_solve(hdl, cp, attr, NULL, B_FALSE);
				nvlist_free(attr);
			} else {
				BUMPSTAT(swde_panic_basecasedata);
				fmd_case_close(hdl, cp);
			}
		} else {
			remain++;
		}


		cp = swde_case_next(hdl, cp);
	}

	if (remain) {
		mytimerid = sw_timer_install(hdl, myid, NULL, NULL,
		    10ULL * NANOSEC * 60);
	}
}

/*
 * Our verify entry point is called for each of our open cases during
 * module load.  We must return 0 for the case to be closed by our caller,
 * or 1 to keep it (or if we have already closed it during this call).
 */
static int
swde_panic_vrfy(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	swde_panic_casedata_t *cdp;
	time_t now = time(NULL);
	nvlist_t *attr;
	uint32_t vers;

	cdp = swde_case_data(hdl, cp, &vers);

	if (vers != SWDE_PANIC_CASEDATA_VERS)
		return (0);	/* case will be closed */

	if (now > cdp->scd_receive_time + 30 * 60) {
		if (nvlist_unpack((char *)cdp + sizeof (*cdp),
		    cdp->scd_nvlbufsz, &attr, 0) == 0) {
			swde_panic_solve(hdl, cp, attr, NULL, B_FALSE);
			nvlist_free(attr);
			return (1);	/* case already closed */
		} else {
			return (0);	/* close case */
		}
	}

	if (mytimerid != 0)
		mytimerid = sw_timer_install(hdl, myid,
		    NULL, NULL, 10ULL * NANOSEC * 60);

	return (1);	/* retain case */
}

/*
 * Handler for ireport.os.sunos.panic.dump_pending_on_device.
 *
 * A future RFE should try adding a means of avoiding diagnosing repeated
 * defects on panic loops, which would just add to the mayhem and potentially
 * log lots of calls through ASR.  Panics with similar enough panic
 * strings and/or stacks should not diagnose to new defects with some
 * period of time, for example.
 */

/*ARGSUSED*/
void
swde_panic_detected(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, void *arg)
{
	boolean_t fm_panic, expect_savecore;
	swde_panic_casedata_t *cdp;
	nvlist_t *attr;
	fmd_case_t *cp;
	char *fmribuf;
	char *uuid;
	size_t sz;

	fmd_hdl_debug(hdl, "swde_panic_detected\n");

	if (nvlist_lookup_nvlist(nvl, FM_IREPORT_ATTRIBUTES, &attr) != 0) {
		BUMPSTAT(swde_panic_noattr);
		return;
	}

	if (nvlist_lookup_string(attr, "os-instance-uuid", &uuid) != 0) {
		BUMPSTAT(swde_panic_nouuid);
		return;
	}

	fmd_hdl_debug(hdl, "swde_panic_detected: OS instance %s\n", uuid);

	if (nvlist_lookup_boolean_value(attr, "fm-panic", &fm_panic) != 0 ||
	    fm_panic == B_TRUE) {
		BUMPSTAT(swde_panic_unexpected_fm_panic);
		return;
	}

	/*
	 * Prepare serialization data to be associated with a new
	 * case.  Our serialization data consists of a swde_panic_casedata_t
	 * structure followed by a packed nvlist of the attributes of
	 * the initial event.
	 */
	if (nvlist_size(attr, &sz, NV_ENCODE_NATIVE) != 0) {
		BUMPSTAT(swde_panic_failsrlz);
		return;
	}

	cdp = fmd_hdl_zalloc(hdl, sizeof (*cdp) + sz, FMD_SLEEP);
	fmribuf = (char *)cdp + sizeof (*cdp);
	cdp->scd_vers = SWDE_PANIC_CASEDATA_VERS;
	cdp->scd_receive_time = time(NULL);
	cdp->scd_nvlbufsz = sz;

	/*
	 * Open a case with UUID matching the the panicking kernel, add this
	 * event to the case.
	 */
	if ((cp = swde_case_open(hdl, myid, uuid, SWDE_PANIC_CASEDATA_VERS,
	    cdp, sizeof (*cdp) + sz)) == NULL) {
		BUMPSTAT(swde_panic_dupuuid);
		fmd_hdl_debug(hdl, "swde_case_open returned NULL - dup?\n");
		fmd_hdl_free(hdl, cdp, sizeof (*cdp) + sz);
		return;
	}

	fmd_case_setprincipal(hdl, cp, ep);

	if (nvlist_lookup_boolean_value(attr, "will-attempt-savecore",
	    &expect_savecore) != 0 || expect_savecore == B_FALSE) {
		fmd_hdl_debug(hdl, "savecore not being attempted - "
		    "solve now\n");
		swde_panic_solve(hdl, cp, attr, ep, B_FALSE);
		return;
	}

	/*
	 * We expect to see either a "dump_available" or a "savecore_failed"
	 * event before too long.  In case that never shows up, for whatever
	 * reason, we want to be able to solve the case anyway.
	 */
	fmd_case_add_ereport(hdl, cp, ep);
	(void) nvlist_pack(attr, &fmribuf, &sz, NV_ENCODE_NATIVE, 0);
	swde_case_data_write(hdl, cp);

	if (mytimerid == 0) {
		mytimerid = sw_timer_install(hdl, myid, NULL, ep,
		    10ULL * NANOSEC * 60);
		fmd_hdl_debug(hdl, "armed timer\n");
	} else {
		fmd_hdl_debug(hdl, "timer already armed\n");
	}
}

/*
 * savecore has now run and saved a crash dump to the filesystem. It is
 * either a compressed dump (vmdump.n) or uncompressed {unix.n, vmcore.n}
 * Savecore has raised an ireport to say the dump is there.
 */

/*ARGSUSED*/
void
swde_panic_savecore_done(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, void *arg)
{
	boolean_t savecore_success = (arg != NULL);
	boolean_t fm_panic;
	nvlist_t *attr;
	fmd_case_t *cp;
	char *uuid;

	fmd_hdl_debug(hdl, "savecore_done (%s)\n", savecore_success ?
	    "success" : "fail");

	if (nvlist_lookup_nvlist(nvl, FM_IREPORT_ATTRIBUTES, &attr) != 0) {
		BUMPSTAT(swde_panic_noattr);
		return;
	}

	if (nvlist_lookup_boolean_value(attr, "fm-panic", &fm_panic) != 0 ||
	    fm_panic == B_TRUE) {
		return;		/* not expected, but just in case */
	}

	if (nvlist_lookup_string(attr, "os-instance-uuid", &uuid) != 0) {
		BUMPSTAT(swde_panic_nouuid);
		return;
	}

	/*
	 * Find the case related to the panicking kernel; our cases have
	 * the same uuid as the crashed OS image.
	 */
	cp = fmd_case_uulookup(hdl, uuid);
	if (!cp) {
		/* Unable to find the case. */
		fmd_hdl_debug(hdl, "savecore_done: can't find case for "
		    "image %s\n", uuid);
		BUMPSTAT(swde_panic_nocase);
		return;
	}

	fmd_hdl_debug(hdl, "savecore_done: solving case %s\n", uuid);
	swde_panic_solve(hdl, cp, attr, ep, savecore_success);
}

const struct sw_disp swde_panic_disp[] = {
	{ SW_SUNOS_PANIC_DETECTED, swde_panic_detected, NULL },
	{ SW_SUNOS_PANIC_AVAIL, swde_panic_savecore_done, (void *)1 },
	{ SW_SUNOS_PANIC_FAILURE, swde_panic_savecore_done, NULL },
	/*
	 * Something has to subscribe to every fault
	 * or defect diagnosed in fmd.  We do that here, but throw it away.
	 */
	{ SW_SUNOS_PANIC_DEFECT, NULL, NULL },
	{ NULL, NULL, NULL }
};

/*ARGSUSED*/
int
swde_panic_init(fmd_hdl_t *hdl, id_t id, const struct sw_disp **dpp,
    int *nelemp)
{
	myid = id;

	if (getzoneid() != GLOBAL_ZONEID)
		return (SW_SUB_INIT_FAIL_VOLUNTARY);

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (swde_panic_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&swde_panic_stats);

	fmd_hdl_subscribe(hdl, SW_SUNOS_PANIC_DETECTED);
	fmd_hdl_subscribe(hdl, SW_SUNOS_PANIC_FAILURE);
	fmd_hdl_subscribe(hdl, SW_SUNOS_PANIC_AVAIL);

	*dpp = &swde_panic_disp[0];
	*nelemp = sizeof (swde_panic_disp) / sizeof (swde_panic_disp[0]);
	return (SW_SUB_INIT_SUCCESS);
}

void
swde_panic_fini(fmd_hdl_t *hdl)
{
	if (mytimerid)
		sw_timer_remove(hdl, myid, mytimerid);
}

const struct sw_subinfo panic_diag_info = {
	"panic diagnosis",		/* swsub_name */
	SW_CASE_PANIC,			/* swsub_casetype */
	swde_panic_init,		/* swsub_init */
	swde_panic_fini,		/* swsub_fini */
	swde_panic_timeout,		/* swsub_timeout */
	NULL,				/* swsub_case_close */
	swde_panic_vrfy,		/* swsub_case_vrfy */
};
