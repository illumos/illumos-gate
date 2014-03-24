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
 * Copyright (c) 2014 Gary Mills
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/pte.h>
#include <sys/cpr.h>

/*
 * Support routines for CPR statistic collection
 */
struct cpr_event cpr_events_buf[CPR_E_MAX_EVENTNUM];

extern struct cpr_terminator cpr_term;

struct cpr_event *cpr_find_event(char *name, int new);

#define	CPR_DEFAULT_PROMTIME		30
#define	CE_START_MASK			0x8000000

/*
 * Use ctp to specify another time point instead of the current time;
 * Otherwise, ctp is NULL.
 */
void
cpr_stat_event_start(char *name, cpr_time_t *ctp)
{
	struct cpr_event *cep;
	cpr_time_t tv;

	if (ctp)
		tv = *ctp;
	else {
		/* need relative time even when hrestime is stoped */
		cpr_tod_get(&tv);
	}

	if ((cep = cpr_find_event(name, 1)) == NULL) {
		cpr_err(CE_WARN, "cpr_stat: run out of event buffers");
		return;
	}
	/*
	 * disallow entering start twice without calling end first
	 */
	if (cep->ce_ntests & CE_START_MASK)
		return;

	cep->ce_ntests |= CE_START_MASK;
	cep->ce_sec.stime = cep->ce_sec.etime = tv.tv_sec;
	cep->ce_sec.ltime = 0;
	cep->ce_msec.stime = cep->ce_msec.etime = tv.tv_nsec / 100000000;
	cep->ce_msec.ltime = 0;
}

void
cpr_stat_event_end(char *name, cpr_time_t *ctp)
{
	struct cpr_stat *cp = STAT;
	struct cpr_event *cep;
	cpr_time_t tv;

	if (ctp)
		tv = *ctp;
	else
		cpr_tod_get(&tv);

	if ((cep = cpr_find_event(name, 0)) == NULL) {
#ifdef CPR_STAT
		prom_printf("cpr_stat: event \"%s\" is not monitored\n", name);
#endif /* CPR_STAT */
		return;
	}

	/*
	 * diallow entering end twice without calling end first
	 */
	if (!(cep->ce_ntests & CE_START_MASK))
		return;

	cep->ce_ntests &= ~CE_START_MASK;
	cep->ce_ntests++;

	/*
	 * calculate seconds
	 */
	cep->ce_sec.etime = tv.tv_sec;
	cep->ce_sec.ltime = cep->ce_sec.etime - cep->ce_sec.stime;
	cep->ce_sec.mtime = ((cep->ce_sec.mtime * (cep->ce_ntests - 1)) +
	    cep->ce_sec.ltime) / cep->ce_ntests;

	/*
	 * calculate 100*milliseconds
	 */
	if (cep->ce_sec.ltime == 0) {
		cep->ce_msec.etime = tv.tv_nsec / 100000000;
		cep->ce_msec.ltime =
		    (cep->ce_msec.etime <= cep->ce_msec.stime) ? 0 :
		    (cep->ce_msec.etime - cep->ce_msec.stime);
		cep->ce_msec.mtime =
		    ((cep->ce_msec.mtime * (cep->ce_ntests - 1)) +
		    cep->ce_msec.ltime) / cep->ce_ntests;
	}
	cp->cs_ntests = cep->ce_ntests & ~CE_START_MASK;
}

void
cpr_stat_cleanup()
{
	struct cpr_stat *cp = STAT;
	struct cpr_event *cep;

	for (cep = cp->cs_event_head; cep; cep = cep->ce_next) {
		if ((cep->ce_ntests & CE_START_MASK) &&
		    strcmp(cep->ce_name, "POST CPR DELAY") != NULL) {
			cpr_stat_event_end(cep->ce_name, 0);
			cep->ce_ntests &= ~CE_START_MASK;
		}
	}
}

void
cpr_stat_init()
{
	STAT->cs_real_statefsz = 0;
	STAT->cs_dumped_statefsz = 0;
}

void
cpr_stat_record_events()
{
	if (cpr_term.real_statef_size) {
		int cur_comprate;

		STAT->cs_real_statefsz = cpr_term.real_statef_size;
		cur_comprate = ((longlong_t)((longlong_t)
		    STAT->cs_nocomp_statefsz*100)/
		    STAT->cs_real_statefsz);
		if (STAT->cs_min_comprate == 0 ||
		    (STAT->cs_min_comprate > cur_comprate))
			STAT->cs_min_comprate = cur_comprate;
	}
}

void
cpr_stat_event_print()
{
	struct cpr_stat *cp = STAT;
	struct cpr_event *cep;
	char *fmt, *tabs;
	int len;

	printf("\n");
	printf("---------------\t\tCPR PERFORMANCE SUMMARY\t\t-------------\n");
	printf("Events\t\t\tRepeat[times]\tMeantime[sec]\tLastEvnt[sec]\n");

	for (cep = cp->cs_event_head; cep; cep = cep->ce_next) {
		len = strlen(cep->ce_name);
		if (len < 8)
			tabs = "\t\t\t";
		else if (len < 16)
			tabs = "\t\t";
		else
			tabs = "\t";
		if (strcmp(cep->ce_name, "Suspend Total") == NULL ||
		    strcmp(cep->ce_name, "Resume Total") == NULL ||
		    strcmp(cep->ce_name, "POST CPR DELAY") == NULL ||
		    strcmp(cep->ce_name, "WHOLE CYCLE") == NULL)
			fmt = "%s%s%d\t\t%3d.%1d\t\t%3d.%1d\n";
		else
			fmt = "%s%s%d\t\t  %3d.%1d\t\t  %3d.%1d\n";
		printf(fmt, cep->ce_name, tabs, (int)cep->ce_ntests,
		    (int)cep->ce_sec.mtime, (int)(cep->ce_msec.mtime / 10),
		    (int)cep->ce_sec.ltime, (int)(cep->ce_msec.ltime / 10));
	}
	delay(drv_usectohz(10000)); /* otherwise the next line goes to prom */
	/*
	 * print the rest of the stat data
	 */
	printf("\nMISCELLANEOUS STATISTICS INFORMATION (units in KBytes)\n\n");
	printf("\tUser Pages w/o Swapspace:\t%8lu (%lu pages)\n",
	    cp->cs_nosw_pages*PAGESIZE/1000, cp->cs_nosw_pages);
	printf("\tTotal Upages Saved to Statefile:%8d (%d pages)\n",
	    cp->cs_upage2statef*PAGESIZE/1000, cp->cs_upage2statef);
	if (cp->cs_mclustsz)
		printf("\tAverage Cluster Size:\t\t%8d (%d.%1d%1d pages)\n\n",
		    cp->cs_mclustsz/1000, cp->cs_mclustsz/PAGESIZE,
		    ((cp->cs_mclustsz%PAGESIZE)*10/PAGESIZE),
		    ((cp->cs_mclustsz%PAGESIZE)*100/PAGESIZE)%10);
	printf("\tKernel Memory Size:\t\t%8lu\n", cp->cs_nocomp_statefsz/1000);
	printf("\tEstimated Statefile Size:\t%8lu\n", cp->cs_est_statefsz/1000);
	printf("\tActual Statefile Size:\t\t%8lu\n", cp->cs_real_statefsz/1000);
	if (cp->cs_real_statefsz) {
		int min = cp->cs_min_comprate;
		int new = ((longlong_t)((longlong_t)
		    cp->cs_nocomp_statefsz*100)/cp->cs_real_statefsz);

		printf("\tCompression Ratio:\t\t%5d.%1d%1d (worst %d.%1d%1d)\n",
		    new/100, (new%100)/10, new%10,
		    min/100, (min%100)/10, min%10);
	}
}

struct cpr_event *
cpr_find_event(char *name, int new)
{
	struct cpr_stat *cp = STAT;
	struct cpr_event *cep;
	int i;

	for (cep = cp->cs_event_head; cep; cep = cep->ce_next) {
		if (strcmp(name, cep->ce_name) == NULL)
			return (cep);
	}

	/* if not begin not end either */
	if (new == NULL)
		return (NULL);

	for (i = 0; i < CPR_E_MAX_EVENTNUM; i++) {
		for (cep = cp->cs_event_head; cep; cep = cep->ce_next) {
			if (&cpr_events_buf[i] == cep)
				break;
		}
		if (!cep) {
			struct cpr_event *new_cep;

			new_cep = &cpr_events_buf[i];
			(void) strcpy(new_cep->ce_name, name);

			if (!cp->cs_event_head) {
				/* The 1st one */
				cp->cs_event_head = new_cep;
			} else {
				/* insert to tail */
				new_cep->ce_next = cp->cs_event_tail->ce_next;
				cp->cs_event_tail->ce_next = new_cep;
			}
			cp->cs_event_tail = new_cep;
			return (new_cep);
		}
	}
	return (NULL);
}

static time_t min_promtime;

void
cpr_convert_promtime(cpr_time_t *pop)
{
	time_t pwroff_time, cb_time;
	cpr_time_t *startp, *shdnp, *endp;

	startp = &cpr_term.tm_cprboot_start;
	shdnp = &cpr_term.tm_shutdown;
	endp = &cpr_term.tm_cprboot_end;

	cb_time = endp->tv_sec - startp->tv_sec;

	cpr_tod_get(endp);
	startp->tv_sec = endp->tv_sec - cb_time;

	if (min_promtime == 0 ||
	    min_promtime > (endp->tv_sec - shdnp->tv_sec - cb_time))
		min_promtime = endp->tv_sec - shdnp->tv_sec - cb_time;

	if (min_promtime > CPR_DEFAULT_PROMTIME)
		min_promtime = CPR_DEFAULT_PROMTIME;

	pwroff_time = startp->tv_sec - shdnp->tv_sec - min_promtime;

	wholecycle_tv.tv_sec += pwroff_time; /* offset the poweroff time */

	pop->tv_sec = startp->tv_sec - min_promtime;
}
