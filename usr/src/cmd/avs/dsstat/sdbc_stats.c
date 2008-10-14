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
#include <inttypes.h>

#include <kstat.h>

#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/sd_bcache.h>

#include "sdbc_stats.h"

#include "dsstat.h"
#include "common.h"
#include "report.h"

static sdbcstat_t *sdbc_top;
kstat_t *sdbc_global = NULL;

void sdbc_header();
int sdbc_value_check(sdbcstat_t *);
int sdbc_validate(kstat_t *);
uint32_t sdbc_getdelta(sdbcstat_t *, char *);

void sdbc_addstat(sdbcstat_t *);
sdbcstat_t *sdbc_delstat(sdbcstat_t *);
void center(int, char *);

/*
 * sdbc_discover() - looks for new statistics to be monitored.
 * Verifies that any statistics found are now already being
 * monitored.
 *
 */
int
sdbc_discover(kstat_ctl_t *kc)
{
	static int validated = 0;

	kstat_t *ksp;

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		int kinst;
		char kname[KSTAT_STRLEN + 1];
		sdbcstat_t *cur;
		sdbcstat_t *sdbcstat = NULL;
		kstat_t *io_ksp;

		if (strcmp(ksp->ks_module, SDBC_KSTAT_MODULE) != 0 ||
		    strncmp(ksp->ks_name, SDBC_KSTAT_CDSTATS, 2) != 0)
			continue;

		if (kstat_read(kc, ksp, NULL) == -1)
			continue;

		/*
		 * Validate kstat structure
		 */
		if (! validated) {
			if (sdbc_validate(ksp))
				return (EINVAL);

			validated++;
		}

		/*
		 * Duplicate check
		 */
		for (cur = sdbc_top; cur; cur = cur->next) {
			char *cur_vname, *tst_vname;

			cur_vname = kstat_value(cur->pre_set,
			    SDBC_CDKSTAT_VOL_NAME);

			tst_vname = kstat_value(ksp,
			    SDBC_CDKSTAT_VOL_NAME);

			if (strncmp(cur_vname, tst_vname, NAMED_LEN) == 0)
				goto next;
		}

		/*
		 * Initialize new record
		 */
		sdbcstat = (sdbcstat_t *)calloc(1, sizeof (sdbcstat_t));

		kinst = ksp->ks_instance;

		/*
		 * Set kstat
		 */
		sdbcstat->pre_set = kstat_retrieve(kc, ksp);

		if (sdbcstat->pre_set == NULL)
			goto next;

		sdbcstat->collected |= GOT_SET_KSTAT;

		/*
		 * I/O kstat
		 */
		sprintf(kname, "%s%d",  SDBC_IOKSTAT_CDSTATS, kinst);

		io_ksp = kstat_lookup(kc, SDBC_KSTAT_MODULE, kinst, kname);
		sdbcstat->pre_io = kstat_retrieve(kc, io_ksp);

		if (sdbcstat->pre_io == NULL)
			goto next;

		sdbcstat->collected |= GOT_IO_KSTAT;

next:
		/*
		 * Check if we got a complete set of stats
		 */
		if (sdbcstat == NULL)
			continue;

		if (SDBC_COMPLETE(sdbcstat->collected)) {
			(void) sdbc_delstat(sdbcstat);
			continue;
		}

		sdbc_addstat(sdbcstat);
	}

	if (sdbc_top == NULL)
		return (EAGAIN);

	return (0);
}

/*
 * sdbc_update() - updates all of the statistics currently being monitored.
 *
 */
int
sdbc_update(kstat_ctl_t *kc)
{
	kstat_t *ksp;
	sdbcstat_t *cur;

	/* Update global kstat information */
	ksp = kstat_lookup(kc, SDBC_KSTAT_MODULE, -1, SDBC_KSTAT_GSTATS);

	if (ksp == NULL)
		return (EAGAIN);

	if (sdbc_global)
		kstat_free(sdbc_global);

	sdbc_global = kstat_retrieve(kc, ksp);

	for (cur = sdbc_top; cur != NULL; cur = cur->next) {
		int kinst;
		char *kname, *cname, *pname;

		kstat_t *set_ksp, *io_ksp;

		cur->collected = 0;

		/*
		 * Age off old stats
		 */
		if (cur->cur_set != NULL) {
			kstat_free(cur->pre_set);
			kstat_free(cur->pre_io);

			cur->pre_set = cur->cur_set;
			cur->pre_io = cur->cur_io;
		}

		/*
		 * Update set kstat
		 */
		kinst = cur->pre_set->ks_instance;
		kname = cur->pre_set->ks_name;

		set_ksp = kstat_lookup(kc, SDBC_KSTAT_MODULE, kinst, kname);

		if ((cur->cur_set = kstat_retrieve(kc, set_ksp)) == NULL)
			continue;

		cur->collected |= GOT_SET_KSTAT;

		/*
		 * Validate set
		 */
		pname = kstat_value(cur->pre_set, SDBC_CDKSTAT_VOL_NAME);
		cname = kstat_value(cur->cur_set, SDBC_CDKSTAT_VOL_NAME);

		if (strncmp(pname, cname, NAMED_LEN) != 0)
			continue;

		/*
		 * Update I/O kstat
		 */
		kinst = cur->pre_io->ks_instance;
		kname = cur->pre_io->ks_name;

		io_ksp = kstat_lookup(kc, SDBC_KSTAT_MODULE, kinst, kname);

		if ((cur->cur_io = kstat_retrieve(kc, io_ksp)) == NULL)
			continue;

		cur->collected |= GOT_IO_KSTAT;
	}

	return (0);
}

/*
 * sdbc_report() - outputs statistics for the statistics currently being
 * monitored.  Deletes statistics for volumes that have been disabled.
 *
 */
int
sdbc_report()
{
	vslist_t *vslist = vs_top;
	sdbcstat_t *cur, *pre = NULL;

	if (sdbc_top == NULL)
		return (0);

	for (cur = sdbc_top; cur != NULL; ) { /* CSTYLED */
		static uint32_t linesout = 0;
		uint32_t *offline;

		char volname[NAMED_LEN + 1];
		char rmode[STAT_HDR_SIZE];
		char wmode[STAT_HDR_SIZE];

		/* Parse volume name */
		strncpy(volname, kstat_value(cur->pre_set,
		    SDBC_CDKSTAT_VOL_NAME), NAMED_LEN);
		volname[NAMED_LEN] = '\0';

		/* Check to see if the user specified this volume */
		for (vslist = vs_top; vslist != NULL; vslist = vslist->next)
			if (strcmp(volname, vslist->volname) == 0)
				break;

		if (vs_top != NULL && vslist == NULL)
			goto next;

		/* Check if volume is offline and zflag applies */
		if (zflag && sdbc_value_check(cur) == 0)
			goto next;

		/* Output volume name */
		sdbc_header();

		(void) printf(DATA_C16, volname);

		if (SDBC_COMPLETE(cur->collected)) {
			sdbcstat_t *next = sdbc_delstat(cur);

			if (! pre)
				cur = sdbc_top = next;
			else
				cur = pre->next = next;

			(void) printf(" <<volume disabled>>\n");
			continue;
		}

		offline = kstat_value(cur->cur_set, SDBC_CDKSTAT_FAILED);
		if (*offline) {
			(void) printf(" <<volume offline>>\n");
			linesout++;
			goto next;
		}

		/* Type/status flags */
		if (dflags & FLAGS) {

			uint32_t *dhint, *nhint;
			uint32_t hints;

			dhint = kstat_value(cur->cur_set, SDBC_CDKSTAT_CDHINTS);
			nhint = kstat_value(sdbc_global, SDBC_GKSTAT_NODEHINTS);

			if (! nhint)
				return (EINVAL);

			hints = *nhint;
			hints &= (NSC_FORCED_WRTHRU | NSC_NO_FORCED_WRTHRU |
			    NSC_NOCACHE);
			hints |= *dhint;

			if (hints & NSC_NOCACHE)
				(void) strcpy(rmode, "D");
			else
				(void) strcpy(rmode, "C");

			if ((hints & NSC_FORCED_WRTHRU) || (hints & NSC_WRTHRU))
				(void) strcpy(wmode, "D");
			else
				(void) strcpy(wmode, "C");

			(void) printf(DATA_C2, rmode);
			(void) printf(DATA_C2, wmode);
		}

		/* Output set information */
		cd_report(cur);

next:
		pre = cur;
		cur = cur->next;
	}

	return (0);
}

/*
 * sdbc_header() - outputs an appropriate header by referencing the
 * global variables dflsgs
 *
 */
void
sdbc_header()
{
	int rcount = 0;

	if (hflags == HEADERS_EXL)
		if ((linesout % DISPLAY_LINES) != 0)
			return;

	if (hflags == HEADERS_BOR)
		if (linesout != 0)
			return;

	if (hflags & HEADERS_ATT)
		if (hflags & HEADERS_OUT)
			return;
		else
			hflags |= HEADERS_OUT;

	if (linesout)
		printf("\n");

	/* first line header */
	if (! (dflags & SUMMARY) && dflags != FLAGS) {

		(void) printf(VOL_HDR_FMT, " ");

		if (dflags & FLAGS) {
			(void) printf(STAT_HDR_FMT, " ");
			(void) printf(STAT_HDR_FMT, " ");
		}

		if (dflags & READ) {
			int size;

			size = KPS_HDR_SIZE * 2 + HIT_HDR_SIZE;
			center(size, "- read -");
			rcount++;
		}

		if (dflags & WRITE) {
			int size;

			size = KPS_HDR_SIZE * 2 + HIT_HDR_SIZE;
			center(size, "- write -");
			rcount++;
		}

		if (dflags != FLAGS)
			(void) printf("\n");
	}

	/* second line header */
	(void) printf(VOL_HDR_FMT, "volume");

	if (dflags & FLAGS) {
		(void) printf(STAT_HDR_FMT, "rd");
		(void) printf(STAT_HDR_FMT, "wr");
	}

	if (dflags & SUMMARY) {
		(void) printf(KPS_HDR_FMT, "ckps");
		(void) printf(KPS_HDR_FMT, "dkps");
		(void) printf(HIT_HDR_FMT, HIT_HDR_TXT);

		goto out;
	}

	if (dflags & READ) {
		(void) printf(KPS_HDR_FMT, "ckps");
		(void) printf(KPS_HDR_FMT, "dkps");
		(void) printf(HIT_HDR_FMT, RHIT_HDR_TXT);
	}

	if (dflags & WRITE) {
		(void) printf(KPS_HDR_FMT, "ckps");
		(void) printf(KPS_HDR_FMT, "dkps");
		(void) printf(HIT_HDR_FMT, WHIT_HDR_TXT);
	}

	if (dflags & DESTAGED)
		(void) printf(KPS_HDR_FMT, "dstg");

	if (dflags & WRCANCEL)
		(void) printf(KPS_HDR_FMT, "cwrl");

out:
	(void) printf("\n");
}

/*
 * sdbc_getstat() - find cache stat by name matching
 *
 * paraemters
 * 	char *vn - the volume name to match against
 * returns
 * 	sdbcstat_t * - the matching strcture, NULL if not found
 */
sdbcstat_t *
sdbc_getstat(char *vn)
{
	sdbcstat_t *cur, *pre = NULL;

	for (cur = sdbc_top; cur; ) { /* CSTYLED */
		char *volname =
		    kstat_value(cur->pre_set, SDBC_CDKSTAT_VOL_NAME);

		if (SDBC_COMPLETE(cur->collected)) {
			sdbcstat_t *next = sdbc_delstat(cur);

			if (! pre)
				cur = sdbc_top = next;
			else
				cur = pre->next = next;

			continue;
		}

		if (strncmp(volname, vn, NAMED_LEN) == 0)
			return (cur);

		pre = cur;
		cur = cur->next;
	}

	return (NULL);
}

/*
 * sdbc_addstat() - adds a fully populated sdbcstat_t structure
 * to the linked list of currently monitored kstats.  The structure
 * will be added in alphabetical order, using the volume name as the
 * key.
 *
 * parameters
 * 	sdbcstat_t *sdbcstat - to be added to the list.
 *
 */
void
sdbc_addstat(sdbcstat_t *sdbcstat)
{
	sdbcstat_t *cur;

	if (sdbc_top == NULL) {
		sdbc_top = sdbcstat;
		return;
	}

	for (cur = sdbc_top; cur != NULL; cur = cur->next) {
		char *cur_vname, *nxt_vname, *tst_vname;

		cur_vname = kstat_value(cur->pre_set,
		    SDBC_CDKSTAT_VOL_NAME);
		tst_vname = kstat_value(sdbcstat->pre_set,
		    SDBC_CDKSTAT_VOL_NAME);

		if (strncmp(cur_vname, tst_vname, NAMED_LEN) > 0) {
			if (cur == sdbc_top)
				sdbc_top = sdbcstat;

			sdbcstat->next = cur;

			return;
		}

		/*
		 * If we get to the last item in the list, then just
		 * add this one to the end
		 */
		if (cur->next == NULL) {
			cur->next = sdbcstat;
			return;
		}

		nxt_vname = kstat_value(cur->next->pre_set,
		    SDBC_CDKSTAT_VOL_NAME);

		if (strncmp(nxt_vname, tst_vname, NAMED_LEN) > 0) {
			sdbcstat->next = cur->next;
			cur->next = sdbcstat;
			return;
		}
	}
}

/*
 * sdbc_delstat() - deallocate memory for the structure being
 * passed in.
 *
 * parameters
 * 	sdbcstat_t *sdbcstat - structure to be deallocated
 *
 * returns
 * 	sdbcstat_t * - pointer to the "next" structures in the
 * 	linked list. May be NULL if we are removing the last
 * 	structure in the linked list.
 */
sdbcstat_t *
sdbc_delstat(sdbcstat_t *sdbcstat)
{

	sdbcstat_t *next = sdbcstat->next;

	kstat_free(sdbcstat->pre_set);
	kstat_free(sdbcstat->pre_io);
	kstat_free(sdbcstat->cur_set);
	kstat_free(sdbcstat->cur_io);

	free(sdbcstat);
	sdbcstat = NULL;

	return (next);
}

/*
 * sdbc_value_check() - Checks for activity, supports -z switch
 *
 * parameters
 * 	sdbcstat_t *sdbcstat - structure to be checked
 *
 * returns
 * 	1 - activity
 * 	0 - no activity
 */
int
sdbc_value_check(sdbcstat_t *sdbcstat)
{
	if (SDBC_COMPLETE(sdbcstat->collected))
		return (1);

	if (sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_CACHE_READ) != 0)
		return (1);

	if (sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_DISK_READ) != 0)
		return (1);

	if (sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_CACHE_WRITE) != 0)
		return (1);

	if (sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_DISK_WRITE) != 0)
		return (1);

	if (sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_WRCANCELNS) != 0)
		return (1);

	if (io_value_check(sdbcstat->pre_io->ks_data,
	    sdbcstat->cur_io->ks_data) != 0)
		return (1);

	return (0);
}

/*
 * sdbc_validate() - validates the structure of the kstats by attempting to
 *                   lookup fields used by this module
 *
 * parameters
 *	kstat_t *ksp - kstat to be examined
 *
 * returns
 * 	1 - one or more fields missing
 * 	0 - all fields present
 */
int
sdbc_validate(kstat_t *ksp)
{
	if (! kstat_value(ksp, SDBC_CDKSTAT_VOL_NAME) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_FAILED) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_CDHINTS) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_CACHE_READ) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_DISK_READ) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_CACHE_WRITE) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_DISK_WRITE) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_DESTAGED) ||
	    ! kstat_value(ksp, SDBC_CDKSTAT_WRCANCELNS))
		return (1);

	return (0);
}

/*
 * sdbc_getvalues() - populates a values structure with data obtained from the
 *                    kstat
 *
 * parameters
 * 	sdbcstat_t *sdbcstat - pointer to the structure containing the kstats
 * 	sdbcvals_t *vals - pointer to the structure that will receive the values
 * 	int flags - flags that describe adjustments made to the values
 *
 * returns
 * 	1 - failure
 * 	0 - success
 */
int
sdbc_getvalues(sdbcstat_t *sdbcstat, sdbcvals_t *vals, int flags)
{
	int divisor = 0;
	int factors;
	uint64_t hr_etime;
	double etime;

	kstat_io_t *cur;
	kstat_io_t *pre;

	if (sdbcstat == NULL)
		return (1);

	cur = sdbcstat->cur_io->ks_data;
	pre = sdbcstat->pre_io->ks_data;

	hr_etime = hrtime_delta(pre->rlastupdate, cur->rlastupdate);
	etime = hr_etime / (double)NANOSEC;

	/* read data */
	vals->cache_read =
	    FBA_SIZE(sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_CACHE_READ));
	vals->disk_read =
	    FBA_SIZE(sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_DISK_READ));


	vals->total_reads = vals->cache_read + vals->disk_read;

	if (vals->cache_read == 0)
		vals->read_hit = 0.0;
	else
		vals->read_hit =
		    ((float)vals->cache_read / vals->total_reads) * 100.0;

	/* write data */
	vals->cache_write =
	    FBA_SIZE(sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_CACHE_WRITE));
	vals->disk_write =
	    FBA_SIZE(sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_DISK_WRITE));

	vals->total_writes = vals->cache_write + vals->disk_write;

	vals->destaged =
		FBA_SIZE(sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_DESTAGED));

	if (vals->cache_write == 0)
		vals->write_hit = 0.0;
	else
		vals->write_hit = ((float)vals->cache_write /
		    (vals->total_writes - vals->destaged)) * 100.0;

	/* miscellaneous */
	vals->write_cancellations =
	    FBA_SIZE(sdbc_getdelta(sdbcstat, SDBC_CDKSTAT_WRCANCELNS));

	vals->total_cache = vals->cache_read + vals->cache_write;
	vals->total_disk = vals->disk_read + vals->disk_write;

	/* total cache hit calculation */
	vals->cache_hit = 0;
	factors = 0;

	if (vals->cache_read != 0) {
		vals->cache_hit += vals->read_hit;
		factors++;
	}

	if (vals->cache_write != 0) {
		vals->cache_hit += vals->write_hit;
		factors++;
	}

	if (vals->cache_hit)
		vals->cache_hit /= (float)factors;

	/* adjustments */
	divisor = 1;

	if (flags & SDBC_KBYTES)
		divisor *= KILOBYTE;
	if ((flags & SDBC_INTAVG) && (etime > 0))
		divisor *= etime;

	if (divisor != 1) {
		vals->cache_read /= divisor;
		vals->disk_read /= divisor;
		vals->total_reads /= divisor;

		vals->cache_write /= divisor;
		vals->disk_write /= divisor;
		vals->total_writes /= divisor;

		vals->total_cache /= divisor;
		vals->total_disk /= divisor;

		vals->destaged /= divisor;
		vals->write_cancellations /= divisor;
	}

	return (0);
}

/*
 * sdbc_getdelta() - calculates the difference between two kstat fields
 *
 * parameters
 * 	sdbcstat_t *sdbcstat - the SDBC stat strcture containing the two fields
 * 	char *name - the name of the fields
 * returns
 * 	uint32_t value of the differences adjusted for overflow of the data type
 */
uint32_t
sdbc_getdelta(sdbcstat_t *sdbcstat, char *name)
{
	uint32_t *cur_val;
	uint32_t *pre_val;

	pre_val = kstat_value(sdbcstat->pre_set, name);
	cur_val = kstat_value(sdbcstat->cur_set, name);

	return (u32_delta(*pre_val, *cur_val));
}

void
center(int size, char *hdr)
{
	int lpad = 0;
	int rpad = 0;
	char fmt[10];

	if (size == 0)
		return;

	if (strlen(hdr) < size) {
		lpad = (size - strlen(hdr)) / 2;

		if (lpad * 2 < size)
			lpad++;

		rpad = size - (lpad + strlen(hdr));
	}

output:
	(void) sprintf(fmt, "%%%ds%%s%%%ds", lpad, rpad);
	(void) printf(fmt, " ", hdr, " ");
}
