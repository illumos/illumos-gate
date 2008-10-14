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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#include <kstat.h>

#include <sys/nsctl/rdc.h>
#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_bitmap.h>

#include "sdbc_stats.h"
#include "sndr_stats.h"

#include "dsstat.h"
#include "common.h"
#include "report.h"

static sndrstat_t *sndr_top;

void sndr_add_stat(sndrstat_t *);
sndrstat_t *sndr_del_stat(sndrstat_t *);

int sndr_value_check(sndrstat_t *);
int sndr_validate(kstat_t *);
int sndr_strcmp(char *, char *);
int sndr_vol_selected(kstat_t *);

void getType(kstat_t *, char *);
void getStat(kstat_t *, char *);
void getQueue(kstat_t *, char *);
void printQueueStats(int, kstat_t *);
float getSyncNeeded(kstat_t *);

static void update_sighandler(int);
static void discover_sighandler(int);

static sigjmp_buf update_env, discover_env;
static sig_atomic_t sig_raised = 0;
/*
 * sndr_discover() - looks for new statistics to be monitored.
 * Verifies that any statistics found are now already being
 * monitored.
 *
 */
int
sndr_discover(kstat_ctl_t *kc)
{
	static int validated = 0;
	struct sigaction segv_act;
	int rc = 0;
	kstat_t *ksp;


	(void) signal(SIGSEGV, discover_sighandler);
	(void) sigaction(SIGSEGV, NULL, &segv_act);

	/* Loop on all kstats */
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		int kinst;
		char kname[KSTAT_STRLEN + 1];
		sndrstat_t *cur;
		sndrstat_t *sndrstat = NULL;
		kstat_t *bmp_ksp;
		kstat_t *sec_ksp;

		/* Serach for SNDR set */
		if (strcmp(ksp->ks_module, RDC_KSTAT_MODULE) != 0 ||
		    strcmp(ksp->ks_name, RDC_KSTAT_INFO) != 0) {
			continue;
		}

		if (kstat_read(kc, ksp, NULL) == -1)
			continue;

		/*
		 * Validate kstat structure
		 */
		if (! validated) {
			if (sndr_validate(ksp))
				return (EINVAL);

			validated++;
		}

		/*
		 * Duplicate check
		 */
		for (cur = sndr_top; cur != NULL; cur = cur->next) {
			char *cur_vname, *tst_vname;
			uint32_t cur_inst, tst_inst;

			cur_vname = kstat_value(cur->pre_set, RDC_IKSTAT_FILE);
			cur_inst = cur->pre_set->ks_instance;

			tst_vname = kstat_value(ksp, RDC_IKSTAT_FILE);
			tst_inst = ksp->ks_instance;

			if (strcmp(cur_vname, tst_vname) == 0 &&
			    cur_inst == tst_inst)
				goto next;
		}

		/*
		 * Initialize new record
		 */
		sndrstat = (sndrstat_t *)calloc(1, sizeof (sndrstat_t));
		kinst = ksp->ks_instance;

		/*
		 * Set kstat
		 */
		sndrstat->pre_set = kstat_retrieve(kc, ksp);

		if (sndrstat->pre_set == NULL)
			goto next;

		sndrstat->collected |= GOT_SET_KSTAT;

		/*
		 * Bitmap kstat
		 */
		(void) sprintf(kname, "%s%d", RDC_KSTAT_BMPNAME, kinst);

		bmp_ksp = kstat_lookup(kc, RDC_KSTAT_BMPNAME, kinst, kname);
		sndrstat->pre_bmp = kstat_retrieve(kc, bmp_ksp);

		if (sndrstat->pre_bmp == NULL)
			goto next;

		sndrstat->collected |= GOT_BMP_KSTAT;

		/*
		 * Secondary kstat
		 */
		(void) sprintf(kname, "%s%d", RDC_KSTAT_RDCNAME, kinst);

		sec_ksp = kstat_lookup(kc, RDC_KSTAT_MODULE, kinst, kname);
		sndrstat->pre_sec = kstat_retrieve(kc, sec_ksp);

		if (sndrstat->pre_sec == NULL)
			goto next;

		sndrstat->collected |= GOT_SEC_KSTAT;

next:
		/*
		 * Check if we got a complete set of stats
		 */
		if (sndrstat == NULL)
			continue;

		if (SNDR_COMPLETE(sndrstat->collected)) {
			(void) sndr_del_stat(sndrstat);
			continue;
		}

		/*
		 * Add to linked list
		 */
		sndr_add_stat(sndrstat);
	}

	(void) sigsetjmp(discover_env, 0);
	if (sig_raised) {
		sig_raised = 0;
		rc = -1;
	}
	(void) sigaction(SIGSEGV, &segv_act, NULL);

	return (rc);
}

void
discover_sighandler(int sig)
{
	switch (sig) {
	case SIGSEGV:
		sig_raised = 1;
		siglongjmp(discover_env, sig);
	default:
		exit(sig);
	}
}

void
update_sighandler(int sig)
{
	switch (sig) {
	case SIGSEGV:
		sig_raised = 1;
		siglongjmp(update_env, sig);
	default:
		exit(sig);
	}
}

/*
 * sndr_update() - updates all of the statistics currently being monitored.
 *
 */
int
sndr_update(kstat_ctl_t *kc)
{
	sndrstat_t *cur;
	struct sigaction segv_act;
	int rc = 0;

	(void) signal(SIGSEGV, update_sighandler);
	(void) sigaction(SIGSEGV, NULL, &segv_act);

	for (cur = sndr_top; cur != NULL; cur = cur->next) {
		int kinst;
		char kname[KSTAT_STRLEN + 1];
		kstat_t *ksp = NULL;
		char *cur_vname, *tst_vname;

		cur->collected = 0;

		/*
		 * Age off old stats
		 */
		if (cur->cur_set != NULL) {
			kstat_free(cur->pre_set);
			kstat_free(cur->pre_bmp);
			kstat_free(cur->pre_sec);

			cur->pre_set = cur->cur_set;
			cur->pre_bmp = cur->cur_bmp;
			cur->pre_sec = cur->cur_sec;
		}

		/*
		 * Set kstat
		 */
		strncpy(kname, cur->pre_set->ks_name, KSTAT_STRLEN);
		kname[KSTAT_STRLEN] = '\0';

		kinst = cur->pre_set->ks_instance;

		ksp = kstat_lookup(kc, RDC_KSTAT_MODULE, kinst, kname);

		if ((cur->cur_set = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_SET_KSTAT;

		/*
		 * Validate set
		 */
		cur_vname = kstat_value(cur->pre_set, RDC_IKSTAT_FILE);
		tst_vname = kstat_value(cur->cur_set, RDC_IKSTAT_FILE);

		if (strcmp(cur_vname, tst_vname) != 0)
			continue;

		/*
		 * Bitmap kstat
		 */
		(void) sprintf(kname, "%s%d", RDC_KSTAT_BMPNAME, kinst);

		ksp = kstat_lookup(kc, RDC_KSTAT_BMPNAME, kinst, kname);

		if ((cur->cur_bmp = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_BMP_KSTAT;

		/*
		 * Secondary kstat
		 */
		(void) sprintf(kname, "%s%d", RDC_KSTAT_RDCNAME, kinst);

		ksp = kstat_lookup(kc, RDC_KSTAT_MODULE, kinst, kname);

		if ((cur->cur_sec = kstat_retrieve(kc, ksp)) == NULL)
			continue;

		cur->collected |= GOT_SEC_KSTAT;

	}

	(void) sigsetjmp(update_env, 0);
	if (sig_raised) {
		sig_raised = 0;
		rc = -1;
	}
	(void) sigaction(SIGSEGV, &segv_act, NULL);

	return (rc);
}

/*
 * sndr_report() - outputs statistics for the statistics currently being
 * monitored.  Deletes statistics for volumes that have been disabled.
 *
 */
int
sndr_report()
{
	int padsz;
	char pad[20] = "";
	sndrstat_t *cur, *pre = NULL;

	if (sndr_top == NULL)
		return (0);

	/* Create padding string for secondary report lines */
	padsz = 0;
	if (dflags & FLAGS) {
		padsz += STAT_HDR_SIZE;
		padsz += STAT_HDR_SIZE;
	}

	if (dflags & ASYNC_QUEUE)
		padsz += STAT_HDR_SIZE;

	if (dflags & PCTS)
		padsz += PCT_HDR_SIZE;

	if (padsz) {
		char fmt[20];
		sprintf(fmt, "%%%ds", padsz);
		sprintf(pad, fmt, " ");
	}

	for (cur = sndr_top; cur != NULL; ) { /*CSTYLED */
		int first = 1;
		char data[20] = "";

		/* Check to see if this is this a complete */
		if (SNDR_COMPLETE(cur->collected)) {
			char *c;
			char vn[NSC_MAXPATH + 1];
			sndrstat_t *next;

			/* notify user of set being disabled */
			c = kstat_value(cur->pre_set, RDC_IKSTAT_SECFILE);
			strncpy(vn, c, NSC_MAXPATH);
			vn[NSC_MAXPATH] = '\0';

			printf(DATA_C16, vn);
			printf(" %s\n", RDC_DISABLED);

			next = sndr_del_stat(cur);

			/* free memory and remove stat from list */
			if (! pre)
				cur = sndr_top = next;
			else
				cur = pre->next = next;

			continue;
		}

		/* Check to see if the user specified this volume */
		if (! sndr_vol_selected(cur->pre_set))
			goto next;

		/* Check to see if zflag applies */
		if (zflag && sndr_value_check(cur) == 0)
			goto next;

		/* Calculate flags */
		if (dflags & FLAGS) {
			char c[STAT_HDR_SIZE];
			char vtype[STAT_HDR_SIZE];
			char vstat[STAT_HDR_SIZE];

			getType(cur->cur_set, &c[0]);
			sprintf(vtype, DATA_C2, c);
			strcat(data, vtype);

			getStat(cur->cur_set, &c[0]);
			sprintf(vstat, DATA_C2, c);
			strcat(data, vstat);
		}

		/* Async. queue statistics */
		if (dflags & ASYNC_QUEUE) {
			char c[STAT_HDR_SIZE];
			char qtype[STAT_HDR_SIZE];

			getQueue(cur->cur_set, &c[0]);
			sprintf(qtype, DATA_C2, c);
			strcat(data, qtype);
		}

		/* Calculate sync needed percentages */
		if (dflags & PCTS) {
			char snpct[10];

			sprintf(snpct, DATA_F62, getSyncNeeded(cur->cur_set));
			strcat(data, snpct);
		}

		/* Output */
		if (rflags & SNDR_NET) {
			char *c;
			char type[STAT_HDR_SIZE];
			char vn[NAMED_LEN + 1];

			getType(cur->cur_set, &type[0]);

			if (type[0] == 'S') {
				c = kstat_value(cur->pre_set,
				    RDC_IKSTAT_FILE);
			} else {
				c = kstat_value(cur->pre_set,
				    RDC_IKSTAT_SECFILE);
			}

			/* Only print last 15 characters */
			if (strlen(c) >= NAMED_LEN) {
				c += strlen(c) - NAMED_LEN;
			}
			strncpy(vn, c, NAMED_LEN);
			vn[NAMED_LEN] = '\0';

			header();
			printf(DATA_C16, vn);
			printf("%s", data);
			printf(ROLE_INF_FMT, RDC_SECONDARY);

			/* Async. queue statistics */
			if (dflags & ASYNC_QUEUE)
				printQueueStats(first, cur->cur_set);

			io_report(cur->cur_sec->ks_data, cur->pre_sec->ks_data,
			    sdbc_getstat(vn));
			printf("\n");

			if (first) {
				strcpy(data, strlen(pad) > 0 ? pad : "");
				first = 0;
			}
		}

		if (rflags & SNDR_BMP) {
			char *c;
			char vn[16];

			c = kstat_value(cur->pre_set, RDC_IKSTAT_BITMAP);

			/* Only print last 15 characters */
			if (strlen(c) >= NAMED_LEN) {
				c += strlen(c) - NAMED_LEN;
			}
			strncpy(vn, c, NAMED_LEN);
			vn[NAMED_LEN] = '\0';

			header();
			printf(DATA_C16, vn);
			printf("%s", data);
			printf(ROLE_INF_FMT, RDC_BITMAP);

			/* Async. queue statistics */
			if (dflags & ASYNC_QUEUE)
				printQueueStats(first, cur->cur_set);

			io_report(cur->cur_bmp->ks_data, cur->pre_bmp->ks_data,
			    sdbc_getstat(vn));
			printf("\n");

			if (first) {
				strcpy(data, strlen(pad) > 0 ? pad : "");
				first = 0;
			}
		}
next:
		pre = cur;
		cur = cur->next;
	}

	return (0);
}

/*
 * sndr_add_stat() - adds a fully populated sndrstat_t structure
 * to the linked list of currently monitored kstats.  The structure
 * will be added in alphabetical order, using the volume name as the
 * key.
 *
 * parameters
 * 	sndrstat_t *sndrstat - to be added to the list.
 *
 */
void
sndr_add_stat(sndrstat_t *sndrstat)
{

	sndrstat_t *cur;

	if (sndr_top == NULL) {
		sndr_top = sndrstat;
		return;
	}

	for (cur = sndr_top; cur != NULL; cur = cur->next) {
		char *cur_vname, *nxt_vname, *tst_vname;

		cur_vname = kstat_value(cur->pre_set, RDC_IKSTAT_FILE);
		tst_vname = kstat_value(sndrstat->pre_set, RDC_IKSTAT_FILE);

		if (strcmp(cur_vname, tst_vname) <= 0) {
			/*
			 * If we get to the last item in the list, then just
			 * add this one to the end
			 */
			if (cur->next == NULL) {
				cur->next = sndrstat;
				return;
			}

			nxt_vname = kstat_value(cur->next->pre_set,
			    RDC_IKSTAT_FILE);

			if (strcmp(nxt_vname, tst_vname) > 0) {
				sndrstat->next = cur->next;
				cur->next = sndrstat;
				return;
			}
		} else {
			if (cur == sndr_top)
				sndr_top = sndrstat;

			sndrstat->next = cur;

			return;
		}
	}
}

/*
 * sndr_del_stat() - deallocate memory for the structure being
 * passed in.
 *
 * parameters
 * 	sndrstat_t *sndrstat - structure to be deallocated
 *
 * returns
 * 	sndrstat_t * - pointer to the "next" structures in the
 * 	linked list. May be NULL if we are removing the last
 * 	structure in the linked list.
 *
 */
sndrstat_t *
sndr_del_stat(sndrstat_t *sndrstat)
{

	sndrstat_t *next = sndrstat->next;

	kstat_free(sndrstat->pre_set);
	kstat_free(sndrstat->pre_bmp);
	kstat_free(sndrstat->pre_sec);
	kstat_free(sndrstat->cur_set);
	kstat_free(sndrstat->cur_bmp);
	kstat_free(sndrstat->cur_sec);

	free(sndrstat);

	return (next);
}

/*
 * sndr_value_check() - check to determine if any activity was registered
 * on this volume by checking the previous stats vs. the current stats.
 *
 * parameters
 * 	sndrstat_t *sndrstat - structure to be checked
 *
 * returns
 * 	0 - no activity
 * 	1 - activity
 */
int
sndr_value_check(sndrstat_t *sndrstat)
{
	if (SNDR_COMPLETE(sndrstat->collected))
		return (1);

	if (io_value_check(sndrstat->pre_bmp->ks_data,
	    sndrstat->cur_bmp->ks_data)) {
		return (1);
	}

	if (io_value_check(sndrstat->pre_sec->ks_data,
	    sndrstat->cur_sec->ks_data)) {
		return (1);
	}

	return (0);
}

/*
 * sndr_validate() - validates the fields required by dsstat exist in
 * the kstat_t structure passed in.  This check keeps dsstat from
 * core dumping if the kstat_named_t structures change in any of the
 * services that dsstat monitors.
 *
 * paramaters
 * 	kstat_t *ksp - kstat_t structure to check.  The ks_data field
 * 	should have been populated with a call to kstat_read()
 *
 * returns
 * 	0 - all fields are contained in the kstat
 * 	1 - a field required by dsstat is not in the kstat
 */
int
sndr_validate(kstat_t *ksp)
{
	if (! kstat_value(ksp, RDC_IKSTAT_FILE) ||
	    ! kstat_value(ksp, RDC_IKSTAT_FLAGS) ||
	    ! kstat_value(ksp, RDC_IKSTAT_SYNCFLAGS) ||
	    ! kstat_value(ksp, RDC_IKSTAT_BMPFLAGS) ||
	    ! kstat_value(ksp, RDC_IKSTAT_VOLSIZE) ||
	    ! kstat_value(ksp, RDC_IKSTAT_BITSSET) ||
	    ! kstat_value(ksp, RDC_IKSTAT_QUEUE_TYPE) ||
	    ! kstat_value(ksp, RDC_IKSTAT_ASYNC_ITEMS) ||
	    ! kstat_value(ksp, RDC_IKSTAT_ASYNC_BLOCKS) ||
	    ! kstat_value(ksp, RDC_IKSTAT_ASYNC_ITEM_HWM) ||
	    ! kstat_value(ksp, RDC_IKSTAT_ASYNC_BLOCK_HWM))
		return (1);

	return (0);
}

void
getType(kstat_t *ksp, char *vtype)
{
	uint32_t *set_flags;

	set_flags = kstat_value(ksp, RDC_IKSTAT_FLAGS);

	if (*set_flags & RDC_PRIMARY)
		(void) strcpy(vtype, "P");
	else
		(void) strcpy(vtype, "S");
}

void
getStat(kstat_t *ksp, char *vstat)
{
	uint32_t *set_flags;
	uint32_t *syn_flags;
	uint32_t *bmp_flags;

	set_flags = kstat_value(ksp, RDC_IKSTAT_FLAGS);
	syn_flags = kstat_value(ksp, RDC_IKSTAT_SYNCFLAGS);
	bmp_flags = kstat_value(ksp, RDC_IKSTAT_BMPFLAGS);

	(void) strcpy(vstat, "R");

	if (*set_flags & RDC_SYNCING) {
		if (*set_flags & RDC_SLAVE)
			if (*set_flags & RDC_PRIMARY)
				(void) strcpy(vstat, "RS");
			else
				(void) strcpy(vstat, "SY");
		else
			if (*set_flags & RDC_PRIMARY)
				(void) strcpy(vstat, "SY");
			else
				(void) strcpy(vstat, "RS");
	}

	if (*set_flags & RDC_LOGGING) {
		(void) strcpy(vstat, "L");

		if (*set_flags & RDC_QUEUING)
			(void) strcpy(vstat, "Q");

		if (*set_flags & RDC_DISKQ_FAILED)
			(void) strcpy(vstat, "QF");

		if (*syn_flags & RDC_SYNC_NEEDED)
			(void) strcpy(vstat, "SN");

		if (*syn_flags & RDC_RSYNC_NEEDED)
			(void) strcpy(vstat, "RN");
	}

	if (*syn_flags & RDC_FCAL_FAILED)
		(void) strcpy(vstat, "FF");

	if (*bmp_flags & RDC_BMP_FAILED)
		(void) strcpy(vstat, "BF");

	if (*syn_flags & RDC_VOL_FAILED)
		(void) strcpy(vstat, "VF");
}

void
getQueue(kstat_t *ksp, char *vqueue)
{
	char *qtype;

	(void) strcpy(vqueue, "-");

	qtype = kstat_value(ksp, RDC_IKSTAT_QUEUE_TYPE);

	if (strcmp(qtype, "memory") == 0)
		(void) strcpy(vqueue, "M");

	if (strcmp(qtype, "disk") == 0)
		(void) strcpy(vqueue, "D");
}

float
getSyncNeeded(kstat_t *ksp)
{
	uint32_t *volsize, *bitsset;
	uint32_t bits, segs;
	float pct;

	volsize = kstat_value(ksp, RDC_IKSTAT_VOLSIZE);
	bitsset = kstat_value(ksp, RDC_IKSTAT_BITSSET);

	segs = FBA_TO_LOG_LEN(*volsize);
	bits = *bitsset > 0 ? *bitsset : 0;

	pct  = segs ? ((float)bits/(float)segs) : 0.0;
	pct *= 100;

	return (pct);
}

/*
 * Special handling for compatibility.
 * "dsstat -s <set>" allows set name to be the last 15 chars,
 * due to 15 characters limit of old kstat information.
 *
 * return 0 if:
 * 1) full and partial are same
 * 2) partial is the last 15 chars of full
 */
int
sndr_strcmp(char *full, char *partial)
{
	char *f = full;
	int rc;

	rc = strcmp(full, partial);

	if (rc != 0 &&
	    (strlen(partial) == NAMED_LEN) &&
	    (strlen(full) > NAMED_LEN)) {
		f += strlen(full) - NAMED_LEN;
		rc = strncmp(f, partial, NAMED_LEN);
	}

	return (rc);
}

int
sndr_vol_selected(kstat_t *ksp)
{
	vslist_t *vslist = vs_top;

	for (vslist = vs_top; vslist != NULL; vslist = vslist->next) {
		char *vn;
		char *vh;

		/* If no host specified, check local only */
		if (vslist->volhost == NULL) {
			vn = kstat_value(ksp, RDC_IKSTAT_FILE);

			if (sndr_strcmp(vn, vslist->volname))
				continue;
			else
				break;
		}

		/* Check primary */
		vn = kstat_value(ksp, RDC_IKSTAT_FILE);
		vh = kstat_value(ksp, RDC_IKSTAT_PRIMARY_HOST);

		if (sndr_strcmp(vn, vslist->volname) == 0 &&
		    sndr_strcmp(vh, vslist->volhost) == 0)
			break;

		/* Check secondary */
		vn = kstat_value(ksp, RDC_IKSTAT_SECFILE);
		vh = kstat_value(ksp, RDC_IKSTAT_SECONDARY_HOST);

		if (sndr_strcmp(vn, vslist->volname) == 0 &&
		    sndr_strcmp(vh, vslist->volhost) == 0)
			break;
	}

	if (vs_top != NULL && vslist == NULL)
		return (0);

	return (1);
}

void
printQueueStats(int first, kstat_t *cur_set)
{
	uint32_t *val;

	if (! first) {
		/* Filler for async. queue fields */
		printf(TPS_HDR_FMT, NO_INFO);
		printf(KPS_HDR_FMT, NO_INFO);
		printf(TPS_HDR_FMT, NO_INFO);
		printf(KPS_HDR_FMT, NO_INFO);

		return;
	}

	val = (uint32_t *)kstat_value(cur_set, RDC_IKSTAT_ASYNC_ITEMS);
	printf(TPS_INF_FMT, *val);

	val = (uint32_t *)kstat_value(cur_set, RDC_IKSTAT_ASYNC_BLOCKS);
	printf(KPS_INF_FMT, (float)(*val / 2));

	val = (uint32_t *)kstat_value(cur_set, RDC_IKSTAT_ASYNC_ITEM_HWM);
	printf(TPS_INF_FMT, *val);

	val = (uint32_t *)kstat_value(cur_set, RDC_IKSTAT_ASYNC_BLOCK_HWM);
	printf(KPS_INF_FMT, (float)(*val / 2));
}
