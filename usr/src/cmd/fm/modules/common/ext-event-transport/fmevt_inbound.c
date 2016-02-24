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
 * Receive (on GPEC channels) raw events published by a few select producers
 * using the private libfmevent publication interfaces, and massage those
 * raw events into full protocol events.  Each raw event selects a "ruleset"
 * by which to perform the transformation into a protocol event.
 *
 * Only publication from userland running privileged is supported; two
 * channels are used - one for high-value and one for low-value events.
 * There is some planning in the implementation below for kernel hi and low
 * value channels, and for non-privileged userland low and hi value channels.
 */

#include <fm/fmd_api.h>
#include <fm/libfmevent.h>
#include <uuid/uuid.h>
#include <libsysevent.h>
#include <pthread.h>
#include <libnvpair.h>
#include <strings.h>
#include <zone.h>

#include "fmevt.h"

static struct fmevt_inbound_stats {
	fmd_stat_t raw_callbacks;
	fmd_stat_t raw_noattrlist;
	fmd_stat_t raw_nodetector;
	fmd_stat_t pp_bad_ruleset;
	fmd_stat_t pp_explicitdrop;
	fmd_stat_t pp_fallthrurule;
	fmd_stat_t pp_fanoutmax;
	fmd_stat_t pp_intldrop;
	fmd_stat_t pp_badclass;
	fmd_stat_t pp_nvlallocfail;
	fmd_stat_t pp_nvlbuildfail;
	fmd_stat_t pp_badreturn;
	fmd_stat_t xprt_posted;
} inbound_stats = {
	{ "raw_callbacks", FMD_TYPE_UINT64,
	    "total raw event callbacks from producers" },
	{ "raw_noattrlist", FMD_TYPE_UINT64,
	    "missing attribute list" },
	{ "raw_nodetector", FMD_TYPE_UINT64,
	    "unable to add detector" },
	{ "pp_bad_ruleset", FMD_TYPE_UINT64,
	    "post-process bad ruleset" },
	{ "pp_explicitdrop", FMD_TYPE_UINT64,
	    "ruleset drops event with NULL func" },
	{ "pp_fanoutmax", FMD_TYPE_UINT64,
	    "post-processing produced too many events" },
	{ "pp_intldrop", FMD_TYPE_UINT64,
	    "post-processing requested event drop" },
	{ "pp_badclass", FMD_TYPE_UINT64,
	    "post-processing produced invalid event class" },
	{ "pp_nvlallocfail", FMD_TYPE_UINT64,
	    "fmd_nvl_alloc failed" },
	{ "pp_nvlbuildfail", FMD_TYPE_UINT64,
	    "nvlist_add_foo failed in building event" },
	{ "pp_badreturn", FMD_TYPE_UINT64,
	    "inconsistent number of events returned" },
	{ "xprt_posted", FMD_TYPE_UINT64,
	    "protocol events posted with fmd_xprt_post" },
};

static int isglobalzone;
static char zonename[ZONENAME_MAX];

#define	BUMPSTAT(stat)	inbound_stats.stat.fmds_value.ui64++

#define	CBF_USER	0x1U
#define	CBF_PRIV	0x2U
#define	CBF_LV		0x4U
#define	CBF_HV		0x8U
#define	CBF_ALL		(CBF_USER | CBF_PRIV | CBF_LV | CBF_HV)

static struct fmevt_chaninfo {
	const char *ci_propname;	/* property to get channel name */
	evchan_t *ci_binding;		/* GPEC binding for this channel */
	char ci_sid[MAX_SUBID_LEN];	/* subscriber id */
	uint32_t ci_cbarg;		/* callback cookie */
	uint32_t ci_sflags;		/* subscription flags to use */
} chaninfo[] = {
	{ "user_priv_highval_channel", NULL, { 0 },
		CBF_USER | CBF_PRIV | CBF_HV, EVCH_SUB_KEEP },
	{ "user_priv_lowval_channel", NULL, { 0 },
		CBF_USER | CBF_PRIV | CBF_LV, EVCH_SUB_KEEP },
};

static pthread_cond_t fmevt_cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t fmevt_lock = PTHREAD_MUTEX_INITIALIZER;
static int fmevt_exiting;

static fmd_xprt_t *fmevt_xprt;
static uint32_t fmevt_xprt_refcnt;
static sysevent_subattr_t *subattr;

/*
 * Rulesets we recognize and who handles them.  Additions and changes
 * must follow the Portfolio Review process.  At ths time only
 * the FMEV_RULESET_ON_SUNOS and FMEVT_RULESET_SMF rulesets are
 * formally recognized by that process - the others here are experimental.
 */
static struct fmevt_rs {
	char *rs_pat;
	fmevt_pp_func_t *rs_ppfunc;
	char *rs_namespace;
	char *rs_subsys;
} rulelist[] = {
	{ FMEV_RULESET_SMF, fmevt_pp_smf },
	{ FMEV_RULESET_ON_EREPORT, fmevt_pp_on_ereport },
	{ FMEV_RULESET_ON_SUNOS, fmevt_pp_on_sunos },
	{ FMEV_RULESET_ON_PRIVATE, fmevt_pp_on_private },
	{ FMEV_RULESET_UNREGISTERED, fmevt_pp_unregistered }
};

/*
 * Take a ruleset specification string and separate it into namespace
 * and subsystem components.
 */
static int
fmevt_rs_burst(fmd_hdl_t *hdl, char *ruleset, char **nsp, char **subsysp,
    boolean_t alloc)
{
	char *ns, *s;
	size_t len;

	if (ruleset == NULL || *ruleset == '\0' ||
	    strnlen(ruleset, FMEV_MAX_RULESET_LEN) == FMEV_MAX_RULESET_LEN)
		return (0);

	if (alloc == B_FALSE) {
		s = ruleset;
		ns = strsep(&s, FMEV_RS_SEPARATOR);

		if (s == NULL || s == ns + 1)
			return (0);
	} else {
		if ((s = strstr(ruleset, FMEV_RS_SEPARATOR)) == NULL ||
		    s == ruleset + strlen(ruleset) - 1)
			return (0);

		len = s - ruleset;

		ns = fmd_hdl_alloc(hdl, len + 1, FMD_SLEEP);
		(void) strncpy(ns, ruleset, len);
		ns[len] = '\0';

		s++;
	}

	if (nsp)
		*nsp = ns;	/* caller must free if alloc == B_TRUE */

	if (subsysp)
		*subsysp = s;	/* always within original ruleset string */

	return (1);
}

static int
fmevt_rs_init(fmd_hdl_t *hdl)
{
	int i;

	for (i = 0; i < sizeof (rulelist) / sizeof (rulelist[0]); i++) {
		struct fmevt_rs *rsp = &rulelist[i];

		if (!fmevt_rs_burst(hdl, rsp->rs_pat, &rsp->rs_namespace,
		    &rsp->rs_subsys, B_TRUE))
			return (0);
	}

	return (1);
}

/*
 * Construct a "sw" scheme detector FMRI.
 *
 * We make no use of priv or pri.
 */
/*ARGSUSED3*/
static nvlist_t *
fmevt_detector(nvlist_t *attr, char *ruleset, int user, int priv,
    fmev_pri_t pri)
{
	char buf[FMEV_MAX_RULESET_LEN + 1];
	char *ns, *subsys;
	nvlist_t *obj, *dtcr, *site, *ctxt;
	char *execname = NULL;
	int32_t i32;
	int64_t i64;
	int err = 0;
	char *str;

	(void) strncpy(buf, ruleset, sizeof (buf));
	if (!fmevt_rs_burst(NULL, buf, &ns, &subsys, B_FALSE))
		return (NULL);

	obj = fmd_nvl_alloc(fmevt_hdl, FMD_SLEEP);
	dtcr = fmd_nvl_alloc(fmevt_hdl, FMD_SLEEP);
	site = fmd_nvl_alloc(fmevt_hdl, FMD_SLEEP);
	ctxt = fmd_nvl_alloc(fmevt_hdl, FMD_SLEEP);

	if (obj == NULL || dtcr == NULL || site == NULL || ctxt == NULL) {
		err++;
		goto done;
	}

	/*
	 * Build up 'object' nvlist.
	 */
	if (nvlist_lookup_string(attr, "__fmev_execname", &execname) == 0)
		err += nvlist_add_string(obj, FM_FMRI_SW_OBJ_PATH, execname);

	/*
	 * Build up 'site' nvlist.  We should have source file and line
	 * number and, if the producer was compiled with C99, function name.
	 */
	if (nvlist_lookup_string(attr, "__fmev_file", &str) == 0) {
		err += nvlist_add_string(site, FM_FMRI_SW_SITE_FILE, str);
		(void) nvlist_remove(attr, "__fmev_file", DATA_TYPE_STRING);
	}

	if (nvlist_lookup_string(attr, "__fmev_func", &str) == 0) {
		err += nvlist_add_string(site, FM_FMRI_SW_SITE_FUNC, str);
		(void) nvlist_remove(attr, "__fmev_func", DATA_TYPE_STRING);
	}

	if (nvlist_lookup_int64(attr, "__fmev_line", &i64) == 0) {
		err += nvlist_add_int64(site, FM_FMRI_SW_SITE_LINE, i64);
		(void) nvlist_remove(attr, "__fmev_line", DATA_TYPE_INT64);
	}

	/*
	 * Build up 'context' nvlist.  We do not include contract id at
	 * this time.
	 */

	err += nvlist_add_string(ctxt, FM_FMRI_SW_CTXT_ORIGIN,
	    user ? "userland" : "kernel");

	if (execname) {
		err += nvlist_add_string(ctxt, FM_FMRI_SW_CTXT_EXECNAME,
		    execname);
		(void) nvlist_remove(attr, "__fmev_execname", DATA_TYPE_STRING);
	}

	if (nvlist_lookup_int32(attr, "__fmev_pid", &i32) == 0) {
		err += nvlist_add_int32(ctxt, FM_FMRI_SW_CTXT_PID, i32);
		(void) nvlist_remove(attr, "__fmev_pid", DATA_TYPE_INT32);
	}

	if (!isglobalzone)
		err += nvlist_add_string(ctxt, FM_FMRI_SW_CTXT_ZONE, zonename);

	/* Put it all together */

	err += nvlist_add_uint8(dtcr, FM_VERSION, SW_SCHEME_VERSION0);
	err += nvlist_add_string(dtcr, FM_FMRI_SCHEME, FM_FMRI_SCHEME_SW);
	err += nvlist_add_nvlist(dtcr, FM_FMRI_SW_OBJ, obj);
	err += nvlist_add_nvlist(dtcr, FM_FMRI_SW_SITE, site);
	err += nvlist_add_nvlist(dtcr, FM_FMRI_SW_CTXT, ctxt);

done:
	nvlist_free(obj);
	nvlist_free(site);
	nvlist_free(ctxt);

	if (err == 0) {
		return (dtcr);
	} else {
		nvlist_free(dtcr);
		return (NULL);
	}
}

static int
class_ok(char *class)
{
	static const char *approved[] = {
		FM_IREPORT_CLASS ".",
		FM_EREPORT_CLASS "."
	};

	int i;

	for (i = 0; i < sizeof (approved) / sizeof (approved[0]); i++) {
		if (strncmp(class, approved[i], strlen(approved[i])) == 0)
			return (1);
	}

	return (0);
}

static void
fmevt_postprocess(char *ruleset, nvlist_t *dtcr, nvlist_t *rawattr,
    struct fmevt_ppargs *eap)
{
	uint_t expected = 0, processed = 0;
	char rs2burst[FMEV_MAX_RULESET_LEN + 1];
	char *class[FMEVT_FANOUT_MAX];
	nvlist_t *attr[FMEVT_FANOUT_MAX];
	fmevt_pp_func_t *dispf = NULL;
	char buf[FMEV_MAX_CLASS];
	char *ns, *subsys;
	int i, found = 0;
	uuid_t uu;

	(void) strncpy(rs2burst, ruleset, sizeof (rs2burst));
	if (!fmevt_rs_burst(NULL, rs2burst, &ns, &subsys, B_FALSE)) {
		BUMPSTAT(pp_bad_ruleset);
		return;
	}

	/*
	 * Lookup a matching rule in our table.
	 */
	for (i = 0; i < sizeof (rulelist) / sizeof (rulelist[0]); i++) {
		struct fmevt_rs *rsp = &rulelist[i];

		if (*ns != '*' && *rsp->rs_namespace != '*' &&
		    strcmp(ns, rsp->rs_namespace) != 0)
			continue;

		if (*subsys != '*' && *rsp->rs_subsys != '*' &&
		    strcmp(subsys, rsp->rs_subsys) != 0)
			continue;

		dispf = rsp->rs_ppfunc;
		found = 1;
		break;

	}

	/*
	 * If a ruleset matches but specifies a NULL function then
	 * it's electing to drop the event.  If no rule was matched
	 * then default to unregistered processing.
	 */
	if (dispf == NULL) {
		if (found) {
			BUMPSTAT(pp_explicitdrop);
			return;
		} else {
			BUMPSTAT(pp_fallthrurule);
			dispf = fmevt_pp_unregistered;
		}
	}

	/*
	 * Clear the arrays in which class strings and attribute
	 * nvlists can be returned.  Pass a pointer to our stack buffer
	 * that the callee can use for the first event class (for others
	 * it must fmd_hdl_alloc and we'll free below).  We will free
	 * and nvlists that are returned.
	 */
	bzero(class, sizeof (class));
	bzero(attr, sizeof (attr));
	class[0] = buf;

	/*
	 * Generate an event UUID which will be used for the first
	 * event generated by post-processing; if post-processing
	 * fans out into more than one event the additional events
	 * can reference this uuid (but we don't generate their
	 * UUIDs until later).
	 */
	uuid_generate(uu);
	uuid_unparse(uu, eap->pp_uuidstr);

	/*
	 * Call selected post-processing function.  See block comment
	 * in fmevt.h for a description of this process.
	 */
	expected = (*dispf)(class, attr, ruleset,
	    (const nvlist_t *)dtcr, rawattr,
	    (const struct fmevt_ppargs *)eap);

	if (expected > FMEVT_FANOUT_MAX) {
		BUMPSTAT(pp_fanoutmax);
		return;	/* without freeing class and nvl - could leak */
	} else if (expected == 0) {
		BUMPSTAT(pp_intldrop);
		return;
	}

	/*
	 * Post as many events as the callback completed.
	 */
	for (i = 0; i < FMEVT_FANOUT_MAX; i++) {
		char uuidstr[36 + 1];
		char *uuidstrp;
		nvlist_t *nvl;
		int err = 0;

		if (class[i] == NULL)
			continue;

		if (!class_ok(class[i])) {
			BUMPSTAT(pp_badclass);
			continue;
		}

		if (processed++ == 0) {
			uuidstrp = eap->pp_uuidstr;
		} else {
			uuid_generate(uu);
			uuid_unparse(uu, uuidstr);
			uuidstrp = uuidstr;
		}

		if ((nvl = fmd_nvl_alloc(fmevt_hdl, FMD_SLEEP)) == NULL) {
			BUMPSTAT(pp_nvlallocfail);
			continue;
		}

		err += nvlist_add_uint8(nvl, FM_VERSION, 0);
		err += nvlist_add_string(nvl, FM_CLASS, (const char *)class[i]);
		err += nvlist_add_string(nvl, FM_IREPORT_UUID, uuidstrp);
		err += nvlist_add_nvlist(nvl, FM_IREPORT_DETECTOR, dtcr);
		err += nvlist_add_string(nvl, FM_IREPORT_PRIORITY,
		    fmev_pri_string(eap->pp_pri) ?
		    fmev_pri_string(eap->pp_pri) : "?");

		if (attr[i] != NULL)
			err += nvlist_add_nvlist(nvl, FM_IREPORT_ATTRIBUTES,
			    attr[i]);

		/*
		 * If we post the event into fmd_xport_post then the
		 * transport code is responsible for freeing the nvl we
		 * posted.
		 */
		if (err == 0) {
			fmd_xprt_post(fmevt_hdl, fmevt_xprt, nvl,
			    eap->pp_hrt);
		} else {
			BUMPSTAT(pp_nvlbuildfail);
			nvlist_free(nvl);
		}
	}

	if (processed != expected)
		BUMPSTAT(pp_badreturn);

	for (i = 0; i < FMEVT_FANOUT_MAX; i++) {
		/*
		 * We provided storage for class[0] but any
		 * additional events have allocated a string.
		 */
		if (i > 0 && class[i] != NULL)
			fmd_hdl_strfree(fmevt_hdl, class[i]);

		/*
		 * Free all attribute lists passed in if they are not
		 * just a pointer to the raw attributes
		 */
		if (attr[i] != NULL && attr[i] != rawattr)
			nvlist_free(attr[i]);
	}
}

static int
fmevt_cb(sysevent_t *sep, void *arg)
{
	char *ruleset = NULL, *rawclass, *rawsubclass;
	uint32_t cbarg = (uint32_t)arg;
	nvlist_t *rawattr = NULL;
	struct fmevt_ppargs ea;
	nvlist_t *dtcr;
	int user, priv;
	fmev_pri_t pri;

	BUMPSTAT(raw_callbacks);

	if (cbarg & ~CBF_ALL)
		fmd_hdl_abort(fmevt_hdl, "event receipt callback with "
		    "invalid flags\n");

	user = (cbarg & CBF_USER) != 0;
	priv = (cbarg & CBF_PRIV) != 0;
	pri = (cbarg & CBF_HV ? FMEV_HIPRI : FMEV_LOPRI);

	(void) pthread_mutex_lock(&fmevt_lock);

	if (fmevt_exiting) {
		while (fmevt_xprt_refcnt > 0)
			(void) pthread_cond_wait(&fmevt_cv, &fmevt_lock);
		(void) pthread_mutex_unlock(&fmevt_lock);
		return (0);	/* discard event */
	}

	fmevt_xprt_refcnt++;
	(void) pthread_mutex_unlock(&fmevt_lock);

	ruleset = sysevent_get_vendor_name(sep);	/* must free */
	rawclass = sysevent_get_class_name(sep);	/* valid with sep */
	rawsubclass = sysevent_get_subclass_name(sep);	/* valid with sep */

	if (sysevent_get_attr_list(sep, &rawattr) != 0) {
		BUMPSTAT(raw_noattrlist);
		goto done;
	}

	if ((dtcr = fmevt_detector(rawattr, ruleset, user, priv,
	    pri)) == NULL) {
		BUMPSTAT(raw_nodetector);
		goto done;
	}

	ea.pp_rawclass = rawclass;
	ea.pp_rawsubclass = rawsubclass;
	sysevent_get_time(sep, &ea.pp_hrt);
	ea.pp_user = user;
	ea.pp_priv = priv;
	ea.pp_pri = pri;

	fmevt_postprocess(ruleset, dtcr, rawattr, &ea);
	nvlist_free(dtcr);
done:
	(void) pthread_mutex_lock(&fmevt_lock);

	if (--fmevt_xprt_refcnt == 0 && fmevt_exiting)
		(void) pthread_cond_broadcast(&fmevt_cv);

	(void) pthread_mutex_unlock(&fmevt_lock);

	if (ruleset)
		free(ruleset);

	nvlist_free(rawattr);

	return (0);	/* in all cases consider the event delivered */
}

void
fmevt_init_inbound(fmd_hdl_t *hdl)
{
	char *sidpfx;
	zoneid_t zoneid;
	int i;

	if (!fmevt_rs_init(hdl))
		fmd_hdl_abort(hdl, "error in fmevt_rs_init\n");

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (inbound_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&inbound_stats);

	zoneid = getzoneid();
	isglobalzone = (zoneid == GLOBAL_ZONEID);
	if (getzonenamebyid(zoneid, zonename, sizeof (zonename)) == -1)
		fmd_hdl_abort(hdl, "getzonenamebyid failed");

	if ((subattr = sysevent_subattr_alloc()) == NULL)
		fmd_hdl_abort(hdl, "failed to allocate subscription "
		    "attributes: %s");

	sysevent_subattr_thrcreate(subattr, fmd_doorthr_create, NULL);
	sysevent_subattr_thrsetup(subattr, fmd_doorthr_setup, NULL);

	sidpfx = fmd_prop_get_string(hdl, "sidprefix");
	fmevt_xprt = fmd_xprt_open(hdl, FMD_XPRT_RDONLY, NULL, NULL);

	for (i = 0; i < sizeof (chaninfo) / sizeof (chaninfo[0]); i++) {
		struct fmevt_chaninfo *cip = &chaninfo[i];
		char *channel = fmd_prop_get_string(hdl, cip->ci_propname);
		int err;

		if (sysevent_evc_bind(channel, &cip->ci_binding,
		    EVCH_CREAT | EVCH_HOLD_PEND_INDEF) != 0)
			fmd_hdl_abort(hdl, "failed to bind GPEC channel for "
			    "channel %s", channel);

		(void) snprintf(cip->ci_sid, sizeof (cip->ci_sid),
		    "%s_%c%c%c", sidpfx,
		    cip->ci_cbarg & CBF_USER ? 'u' : 'k',
		    cip->ci_cbarg & CBF_PRIV ? 'p' : 'n',
		    cip->ci_cbarg & CBF_HV ? 'h' : 'l');

		err = sysevent_evc_xsubscribe(cip->ci_binding, cip->ci_sid,
		    EC_ALL, fmevt_cb, (void *)cip->ci_cbarg,
		    cip->ci_sflags, subattr);

		if (err == EEXIST)
			fmd_hdl_abort(hdl, "another fmd is active on "
			    "channel %s\n", channel);
		else if (err != 0)
			fmd_hdl_abort(hdl, "failed to subscribe to channel %s",
			    channel);

		fmd_prop_free_string(hdl, channel);
	}

	fmd_prop_free_string(hdl, sidpfx);
}

void
fmevt_fini_inbound(fmd_hdl_t *hdl)
{
	int i;

	for (i = 0; i < sizeof (chaninfo) / sizeof (chaninfo[0]); i++) {
		struct fmevt_chaninfo *cip = &chaninfo[i];

		if (cip->ci_binding) {
			(void) sysevent_evc_unsubscribe(cip->ci_binding,
			    cip->ci_sid);
			(void) sysevent_evc_unbind(cip->ci_binding);
			cip->ci_binding = NULL;
		}
	}

	if (subattr) {
		sysevent_subattr_free(subattr);
		subattr = NULL;
	}

	if (fmevt_xprt) {
		/* drain before destruction */
		(void) pthread_mutex_lock(&fmevt_lock);
		fmevt_exiting = 1;
		while (fmevt_xprt_refcnt > 0)
			(void) pthread_cond_wait(&fmevt_cv, &fmevt_lock);
		(void) pthread_mutex_unlock(&fmevt_lock);

		fmd_xprt_close(hdl, fmevt_xprt);
	}

}
