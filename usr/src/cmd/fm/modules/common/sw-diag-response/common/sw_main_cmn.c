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
 * Code shared by software-diagnosis and software-response modules.
 * The fmd module linkage info for the two modules lives in swde_main.c
 * (for software-diagnosis) and swrp_main.c (for software-response).
 */

#include "../common/sw_impl.h"

/*
 * Each subsidiary that is hosted is assigned a unique subsidiary id.  These
 * macros convert between the id of a subsidiary and the index used in keeping
 * track of subsidiaries.  Outside of this file these ids should remain
 * opaque.
 */
#define	ID2IDX(id)	((int)((id) & 0xff0000) >> 16)
#define	IDX2ID(i)	((id_t)((i) << 16) | 0x1d000000)

#define	SUBIDVALID(msinfo, id)  (((int)(id) & 0xff00ffff) == 0x1d000000 && \
    ID2IDX(id) < (msinfo)->swms_dispcnt)

static struct {
	fmd_stat_t sw_recv_total;
	fmd_stat_t sw_recv_match;
	fmd_stat_t sw_recv_callback;
} sw_stats = {
	{ "sw_recv_total", FMD_TYPE_UINT64,
	    "total events received" },
	{ "sw_recv_match", FMD_TYPE_UINT64,
	    "events matching some subsidiary" },
	{ "sw_recv_callback", FMD_TYPE_UINT64,
	    "callbacks to all subsidiaries" },
};

#define	BUMPSTAT(stat)		sw_stats.stat.fmds_value.ui64++
#define	BUMPSTATN(stat, n)	sw_stats.stat.fmds_value.ui64 += (n)

/*
 * ========================== Event Receipt =================================
 *
 * The fmdo_recv entry point.  See which sub de/response agents have a
 * matching subscription and callback for the first match from each.
 * The sub de/response agents should dispatch *all* their subscriptions
 * via their registered dispatch table, including things like list.repaired.
 */
void
sw_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	struct sw_modspecific *msinfo;
	int calls = 0;
	int mod;

	BUMPSTAT(sw_recv_total);

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);

	/*
	 * For each sub module that has a matching class pattern call the
	 * registered callback for that sub DE.  Only one match per sub module
	 * is allowed (the first match in its table, others are not checked).
	 */
	for (mod = 0; mod < msinfo->swms_dispcnt; mod++) {
		const struct sw_disp *dp;
		sw_dispfunc_t *dispf = NULL;

		for (dp = (*msinfo->swms_disptbl)[mod];
		    dp != NULL && dp->swd_classpat != NULL; dp++) {
			if (fmd_nvl_class_match(hdl, nvl, dp->swd_classpat)) {
				dispf = dp->swd_func;
				break;
			}
		}
		if (dispf != NULL) {
			calls++;
			(*dispf)(hdl, ep, nvl, class, dp->swd_arg);
		}
	}

	BUMPSTAT(sw_recv_match);
	if (calls)
		BUMPSTATN(sw_recv_callback, calls);
}

/*
 * ========================== Timers ========================================
 *
 * A subsidiary can install a timer; it must pass an additional argument
 * identifying itself so that we can hand off to the appropriate
 * swsub_timeout function in the fmdo_timeout entry point when the timer fires.
 */
id_t
sw_timer_install(fmd_hdl_t *hdl, id_t who, void *arg, fmd_event_t *ep,
    hrtime_t hrt)
{
	struct sw_modspecific *msinfo;
	const struct sw_subinfo **subinfo;
	const struct sw_subinfo *sip;
	int slot, chosen = -1;
	id_t timerid;

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);
	if (!SUBIDVALID(msinfo, who))
		fmd_hdl_abort(hdl, "sw_timer_install: invalid subid %d\n", who);

	subinfo = *msinfo->swms_subinfo;
	sip = subinfo[ID2IDX(who)];

	if (sip-> swsub_timeout == NULL)
		fmd_hdl_abort(hdl, "sw_timer_install: no swsub_timeout\n");

	/*
	 * Look for a slot.  Module entry points are single-threaded
	 * in nature, but if someone installs a timer from a door
	 * service function we're contended.
	 */
	(void) pthread_mutex_lock(&msinfo->swms_timerlock);
	for (slot = 0; slot < SW_TIMER_MAX; slot++) {
		if (msinfo->swms_timers[slot].swt_state != SW_TMR_INUSE) {
			chosen = slot;
			break;
		}
	}

	if (chosen == -1)
		fmd_hdl_abort(hdl, "timer slots exhausted\n");

	msinfo->swms_timers[chosen].swt_state = SW_TMR_INUSE;
	msinfo->swms_timers[chosen].swt_ownerid = who;
	msinfo->swms_timers[chosen].swt_timerid = timerid =
	    fmd_timer_install(hdl, arg, ep, hrt);

	(void) pthread_mutex_unlock(&msinfo->swms_timerlock);

	return (timerid);
}

/*
 * Look for a timer installed by a given subsidiary matching timerid.
 */
static int
subtimer_find(struct sw_modspecific *msinfo, id_t who, id_t timerid)
{
	int slot;

	for (slot = 0; slot < SW_TIMER_MAX; slot++) {
		if (msinfo->swms_timers[slot].swt_state == SW_TMR_INUSE &&
		    (who == -1 ||
		    msinfo->swms_timers[slot].swt_ownerid == who) &&
		    msinfo->swms_timers[slot].swt_timerid == timerid)
			return (slot);
	}

	return (-1);
}

void
sw_timer_remove(fmd_hdl_t *hdl, id_t who, id_t timerid)
{
	struct sw_modspecific *msinfo;
	const struct sw_subinfo **subinfo;
	const struct sw_subinfo *sip;
	int slot;

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);
	if (!SUBIDVALID(msinfo, who))
		fmd_hdl_abort(hdl, "sw_timer_remove: invalid subid\n");

	subinfo = *msinfo->swms_subinfo;
	sip = subinfo[ID2IDX(who)];

	(void) pthread_mutex_lock(&msinfo->swms_timerlock);
	if ((slot = subtimer_find(msinfo, who, timerid)) == -1)
		fmd_hdl_abort(hdl, "sw_timer_remove: timerid %d not found "
		    "for %s\n", timerid, sip->swsub_name);
	fmd_timer_remove(hdl, timerid);
	msinfo->swms_timers[slot].swt_state = SW_TMR_RMVD;
	(void) pthread_mutex_unlock(&msinfo->swms_timerlock);
}

/*
 * The fmdo_timeout entry point.
 */
void
sw_timeout(fmd_hdl_t *hdl, id_t timerid, void *arg)
{
	struct sw_modspecific *msinfo;
	const struct sw_subinfo **subinfo;
	const struct sw_subinfo *sip;
	id_t owner;
	int slot;

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);

	(void) pthread_mutex_lock(&msinfo->swms_timerlock);
	if ((slot = subtimer_find(msinfo, -1, timerid)) == -1)
		fmd_hdl_abort(hdl, "sw_timeout: timerid %d not found\n");
	(void) pthread_mutex_unlock(&msinfo->swms_timerlock);

	owner = msinfo->swms_timers[slot].swt_ownerid;
	if (!SUBIDVALID(msinfo, owner))
		fmd_hdl_abort(hdl, "sw_timeout: invalid subid\n");

	subinfo = *msinfo->swms_subinfo;
	sip = subinfo[ID2IDX(owner)];

	sip->swsub_timeout(hdl, timerid, arg);
}

/*
 * ========================== sw_subinfo access =============================
 */

enum sw_casetype
sw_id_to_casetype(fmd_hdl_t *hdl, id_t who)
{
	struct sw_modspecific *msinfo;
	const struct sw_subinfo **subinfo;
	const struct sw_subinfo *sip;

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);
	if (!SUBIDVALID(msinfo, who))
		fmd_hdl_abort(hdl, "sw_id_to_casetype: invalid subid %d\n",
		    who);

	subinfo = *msinfo->swms_subinfo;
	sip = subinfo[ID2IDX(who)];

	if ((sip->swsub_casetype & SW_CASE_NONE) != SW_CASE_NONE)
		fmd_hdl_abort(hdl, "sw_id_to_casetype: bad case type %d "
		    "for %s\n", sip->swsub_casetype, sip->swsub_name);

	return (sip->swsub_casetype);
}

/*
 * Given a case type lookup the struct sw_subinfo for the subsidiary
 * that opens cases of that type.
 */
static const struct sw_subinfo *
sw_subinfo_bycase(fmd_hdl_t *hdl, enum sw_casetype type)
{
	struct sw_modspecific *msinfo;
	const struct sw_subinfo **subinfo;
	const struct sw_subinfo *sip;
	int i;

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);

	subinfo = *msinfo->swms_subinfo;
	for (i = 0; i < SW_SUB_MAX; i++) {
		sip = subinfo[i];
		if (sip->swsub_casetype == type)
			return (sip);
	}

	return (NULL);
}

/*
 * Find the case close function for the given case type; can be NULL.
 */
swsub_case_close_func_t *
sw_sub_case_close_func(fmd_hdl_t *hdl, enum sw_casetype type)
{
	const struct sw_subinfo *sip;

	if ((sip = sw_subinfo_bycase(hdl, type)) == NULL)
		fmd_hdl_abort(hdl, "sw_sub_case_close_func: case type "
		    "%d not found\n", type);

	return (sip->swsub_case_close);
}

/*
 * Find the case verify function for the given case type; can be NULL.
 */
sw_case_vrfy_func_t *
sw_sub_case_vrfy_func(fmd_hdl_t *hdl, enum sw_casetype type)
{
	const struct sw_subinfo *sip;

	if ((sip = sw_subinfo_bycase(hdl, type)) == NULL)
		fmd_hdl_abort(hdl, "sw_sub_case_vrfy_func: case type "
		    "%d not found\n", type);

	return (sip->swsub_case_verify);
}

/*
 * ========================== Initialization ================================
 *
 * The two modules - software-diagnosis and software-response - call
 * sw_fmd_init from their _fmd_init entry points.
 */

static void
sw_add_callbacks(fmd_hdl_t *hdl, const char *who,
    const struct sw_disp *dp, int nelem, struct sw_modspecific *msinfo)
{
	int i;

	(*msinfo->swms_disptbl)[msinfo->swms_dispcnt++] = dp;

	if (dp == NULL)
		return;		/* subsidiary failed init */

	/* check that the nelem'th entry is the NULL termination */
	if (dp[nelem - 1].swd_classpat != NULL ||
	    dp[nelem - 1].swd_func != NULL || dp[nelem - 1].swd_arg != NULL)
		fmd_hdl_abort(hdl, "subsidiary %s dispatch table not NULL-"
		    "terminated\n", who);

	/* now validate the entries; we allow NULL handlers */
	for (i = 0; i < nelem - 1; i++) {
		if (dp[i].swd_classpat == NULL)
			fmd_hdl_abort(hdl, "subsidiary %s dispatch table entry "
			    "%d has a NULL pattern or function\n", who, i);
	}

}

int
sw_fmd_init(fmd_hdl_t *hdl, const fmd_hdl_info_t *hdlinfo,
    const struct sw_subinfo *(*subsid)[SW_SUB_MAX])
{
	struct sw_modspecific *msinfo;
	int i;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, hdlinfo) != 0)
		return (0);

	if (fmd_prop_get_int32(hdl, "enable") != B_TRUE) {
		fmd_hdl_debug(hdl, "%s disabled though .conf file setting\n",
		    hdlinfo->fmdi_desc);
		fmd_hdl_unregister(hdl);
		return (0);
	}

	msinfo = fmd_hdl_zalloc(hdl, sizeof (*msinfo), FMD_SLEEP);

	msinfo->swms_subinfo = subsid;
	msinfo->swms_disptbl = fmd_hdl_zalloc(hdl,
	    SW_SUB_MAX * sizeof (struct sw_disp *), FMD_SLEEP);

	(void) pthread_mutex_init(&msinfo->swms_timerlock, NULL);

	for (i = 0; i < SW_TIMER_MAX; i++)
		msinfo->swms_timers[i].swt_state = SW_TMR_UNTOUCHED;

	fmd_hdl_setspecific(hdl, (void *)msinfo);

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (sw_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&sw_stats);

	/*
	 * Initialize subsidiaries.  Each must make any subscription
	 * requests it needs and return a pointer to a NULL-terminated
	 * callback dispatch table and an indication of the number of
	 * entries in that table including the NULL termination entry.
	 */
	for (i = 0; i < SW_SUB_MAX; i++) {
		const struct sw_subinfo *sip = (*subsid)[i];
		const struct sw_disp *dp;
		char dbgbuf[80];
		int nelem = -1;
		int initrslt;

		if (!sip || sip->swsub_name == NULL)
			break;

		initrslt = (*sip->swsub_init)(hdl, IDX2ID(i), &dp, &nelem);

		(void) snprintf(dbgbuf, sizeof (dbgbuf),
		    "subsidiary %d (id 0x%lx) '%s'",
		    i, IDX2ID(i), sip->swsub_name);

		switch (initrslt) {
		case SW_SUB_INIT_SUCCESS:
			if (dp == NULL || nelem < 1)
				fmd_hdl_abort(hdl, "%s returned dispatch "
				    "table 0x%p and nelem %d\n",
				    dbgbuf, dp, nelem);

			fmd_hdl_debug(hdl, "%s initialized\n", dbgbuf);
			sw_add_callbacks(hdl, sip->swsub_name, dp, nelem,
			    msinfo);
			break;

		case SW_SUB_INIT_FAIL_VOLUNTARY:
			fmd_hdl_debug(hdl, "%s chose not to initialize\n",
			    dbgbuf);
			sw_add_callbacks(hdl, sip->swsub_name, NULL, -1,
			    msinfo);
			break;

		case SW_SUB_INIT_FAIL_ERROR:
			fmd_hdl_debug(hdl, "%s failed to initialize "
			    "because of an error\n", dbgbuf);
			sw_add_callbacks(hdl, sip->swsub_name, NULL, -1,
			    msinfo);
			break;

		default:
			fmd_hdl_abort(hdl, "%s returned out-of-range result "
			    "%d\n", dbgbuf, initrslt);
			break;
		}
	}

	return (1);
}

void
sw_fmd_fini(fmd_hdl_t *hdl)
{
	const struct sw_subinfo **subinfo;
	struct sw_modspecific *msinfo;
	int i;

	msinfo = (struct sw_modspecific *)fmd_hdl_getspecific(hdl);
	subinfo = *msinfo->swms_subinfo;

	(void) pthread_mutex_lock(&msinfo->swms_timerlock);
	for (i = 0; i < SW_TIMER_MAX; i++) {
		if (msinfo->swms_timers[i].swt_state != SW_TMR_INUSE)
			continue;

		fmd_timer_remove(hdl, msinfo->swms_timers[i].swt_timerid);
		msinfo->swms_timers[i].swt_state = SW_TMR_RMVD;
	}
	(void) pthread_mutex_unlock(&msinfo->swms_timerlock);

	(void) pthread_mutex_destroy(&msinfo->swms_timerlock);

	for (i = 0; i < msinfo->swms_dispcnt; i++) {
		const struct sw_subinfo *sip = subinfo[i];

		if ((*msinfo->swms_disptbl)[i] == NULL)
			continue;	/* swsub_init did not succeed */

		if (sip->swsub_fini != NULL)
			(*sip->swsub_fini)(hdl);
	}

	fmd_hdl_free(hdl, msinfo->swms_disptbl,
	    SW_SUB_MAX * sizeof (struct sw_disp *));

	fmd_hdl_setspecific(hdl, NULL);
	fmd_hdl_free(hdl, msinfo, sizeof (*msinfo));
}
