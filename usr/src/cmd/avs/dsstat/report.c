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
#include <string.h>

#include <kstat.h>
#include <sys/inttypes.h>

#include <nsctl.h>

#include "dsstat.h"
#include "common.h"

#include "sdbc_stats.h"
#include "report.h"

extern short dflags;

/*
 * Return the number of ticks delta between two hrtime_t
 * values. Attempt to cater for various kinds of overflow
 * in hrtime_t - no matter how improbable.
 */
uint64_t
hrtime_delta(hrtime_t old, hrtime_t new)
{

	uint64_t del;

	if ((new >= old) && (old >= 0L)) {
		return (new - old);
	} else {
		/*
		 * We've overflowed the positive portion of an
		 * hrtime_t.
		 */
		if (new < 0L) {
			/*
			 * The new value is negative. Handle the
			 * case where the old value is positive or
			 * negative.
			 */
			uint64_t n1;
			uint64_t o1;

			n1 = -new;

			if (old > 0L) {
				return (n1 - old);
			} else {
				o1 = -old;
				del = n1 - o1;
				return (del);
			}
		} else {
			/*
			 * Either we've just gone from being negative
			 * to positive *or* the last entry was positive
			 * and the new entry is also positive but *less*
			 * than the old entry. This implies we waited
			 * quite a few days on a very fast system between
			 * iostat displays.
			 */
			if (old < 0L) {
				uint64_t o2;

				o2 = -old;
				del = UINT64_MAX - o2;
			} else {
				del = UINT64_MAX - old;
			}

			del += new;

			return (del);
		}
	}
}

/*
 * Take the difference of an unsigned 32
 * bit int attempting to cater for
 * overflow.
 */
uint32_t
u32_delta(uint32_t old, uint32_t new)
{

	if (new >= old)
		return (new - old);
	else
		return ((UINT32_MAX - old) + new + 1);
}

/*
 * Take the difference of an unsigned 64
 * bit int attempting to cater for
 * overflow.
 */
uint64_t
u64_delta(uint64_t old, uint64_t new)
{

	if (new >= old)
		return (new - old);
	else
		return ((UINT64_MAX - old) + new + 1);
}

/*
 * io_report() - diffs and reports data contained in
 * kstat_io_t structures.
 *
 * parameters
 * 	kstat_io_t *cur - pointer to current data
 *
 * 	kstat_io_t *pre - pointer to data as it was
 * 	at the beginning of an interval.
 */
void
io_report(kstat_io_t *cur, kstat_io_t *pre, sdbcstat_t *sdbcstat)
{
	sdbcvals_t vals;

	double rd_cnt, wr_cnt;
	double rd_kb, wr_kb, hr_etime;

	double rtm, tps, avs, etime;

	if (sdbcstat &&
	    sdbc_getvalues(sdbcstat, &vals, (SDBC_KBYTES | SDBC_INTAVG)))
		return;

	/* Time */
	hr_etime = hrtime_delta(pre->wlastupdate, cur->wlastupdate);
	etime = hr_etime / (double)NANOSEC;

	/* Read count */
	rd_cnt = (double)u32_delta(pre->reads, cur->reads);
	if (rd_cnt) rd_cnt /= etime;

	/* Bytes read */
	rd_kb = (double)u64_delta(pre->nread, cur->nread) / KILOBYTE;
	if (rd_kb) rd_kb /= etime;

	/* Write count    */
	wr_cnt = (double)u32_delta(pre->writes, cur->writes);
	if (wr_cnt) wr_cnt /= etime;

	/* Bytes written  */
	wr_kb = (double)u64_delta(pre->nwritten, cur->nwritten) / KILOBYTE;
	if (wr_kb) wr_kb /= etime;

	/* Calculate service times */
	avs = (double)hrtime_delta(pre->rlentime, cur->rlentime) / hr_etime;
	tps = (double)rd_cnt + wr_cnt;

	if (tps > 0)
		rtm = (1000 / tps) * avs;
	else
		rtm = 0.0;

	/* Output */
	if (dflags & SUMMARY) {
		if ((mode & MULTI) && (mode & SDBC)) {
			if (sdbcstat) {
				printf(KPS_INF_FMT, (float)vals.total_cache);
				printf(KPS_INF_FMT, (float)vals.total_disk);
			} else {
				printf(DATA_C6, NO_INFO);
				printf(KPS_INF_FMT, rd_kb + wr_kb);
			}
		} else
			printf(KPS_INF_FMT, rd_kb + wr_kb);

		printf(TPS_INF_FMT, (uint32_t)(rd_cnt + wr_cnt));
		printf(SVT_INF_FMT, rtm);

		goto done;
	}

	if (dflags & READ) {
		if ((mode & MULTI) && (mode & SDBC)) {
			if (sdbcstat) {
				printf(KPS_INF_FMT, (float)vals.cache_read);
				printf(KPS_INF_FMT, (float)vals.disk_read);
			} else {
				printf(DATA_C6, NO_INFO);
				printf(KPS_INF_FMT, rd_kb);
			}

		} else
			printf(KPS_INF_FMT, rd_kb);

		printf(TPS_INF_FMT, (uint32_t)rd_cnt);
	}

	if (dflags & WRITE) {
		if ((mode & MULTI) && (mode & SDBC)) {
			if (sdbcstat) {
				printf(KPS_INF_FMT, (float)vals.cache_write);
				printf(KPS_INF_FMT, (float)vals.disk_write);
			} else {
				printf(DATA_C6, NO_INFO);
				printf(KPS_INF_FMT, wr_kb);
			}

		} else
			printf(KPS_INF_FMT, wr_kb);

		printf(TPS_INF_FMT, (uint32_t)wr_cnt);
	}

	if (dflags & TIMING) {
		printf(SVT_INF_FMT, rtm);
	}

done:
	linesout++;
}

int
io_value_check(kstat_io_t *pre, kstat_io_t *cur)
{
	if (u32_delta(pre->reads, cur->reads))
		return (1);
	if (u32_delta(pre->writes, cur->writes))
		return (1);

	return (0);
}

/*
 * cd_report() - reports cache desriptor related statistics
 * based on the dflags global variable
 *
 * parameters
 * 	sdbcstat_t *sdbcstat - pointer to the cache structure
 * 	to be reported on.
 */
void
cd_report(sdbcstat_t *sdbcstat)
{
	sdbcvals_t vals;

	/* Extract statistics, average for time */
	if (sdbc_getvalues(sdbcstat, &vals, (SDBC_KBYTES | SDBC_INTAVG)))
		return;

	/* Output */
	if (rflags & MULTI) {
		printf(VOL_HDR_FMT, "");

		if (dflags & FLAGS) {
			printf(STAT_HDR_FMT, "");
			printf(STAT_HDR_FMT, "");
		}

		if (dflags & PCTS)
			printf(PCT_HDR_FMT, "");

		if (dflags & SUMMARY) {
			printf(KPS_INF_FMT, (float)vals.total_cache);
			printf(DATA_C4, NO_INFO);
			printf(DATA_C4, NO_INFO);
			printf("\n");
			linesout++;
			return;
		}

		if (dflags & READ) {
			printf(KPS_INF_FMT, (float)vals.cache_read);
			printf(DATA_C4, NO_INFO);
		}

		if (dflags & WRITE) {
			printf(KPS_INF_FMT, (float)vals.cache_write);
			printf(DATA_C4, NO_INFO);
		}

		if (dflags & TIMING) {
			printf(DATA_C4, NO_INFO);
		}

		linesout++;
		printf("\n");
		return;
	}

	if (dflags & SUMMARY) {
		(void) printf(DATA_I32, vals.total_cache);
		(void) printf(DATA_I32, vals.total_disk);
		(void) printf(HIT_INF_FMT, vals.cache_hit);

		linesout++;
		printf("\n");
		return;
	}

	if (dflags & READ) {
		(void) printf(DATA_I32, vals.cache_read);
		(void) printf(DATA_I32, vals.disk_read);
		(void) printf(HIT_INF_FMT, vals.read_hit);
	}

	if (dflags & WRITE) {
		(void) printf(DATA_I32, vals.cache_write);
		(void) printf(DATA_I32, vals.disk_write);
		(void) printf(HIT_INF_FMT, vals.write_hit);
	}

	if (dflags & DESTAGED)
		(void) printf(DATA_I32, vals.destaged);

	if (dflags & WRCANCEL)
		(void) printf(DATA_I32, vals.write_cancellations);

	linesout++;
	printf("\n");
}

/*
 * header() - outputs an appropriate header by referencing the
 * global variables dflsgs and rflags
 *
 */
void
header()
{
	if (hflags & HEADERS_EXL)
		if ((linesout % DISPLAY_LINES) != 0)
			return;

	if (hflags & HEADERS_BOR)
		if (linesout != 0)
			return;

	if (hflags & HEADERS_ATT)
		if (hflags & HEADERS_OUT)
			return;
		else
			hflags |= HEADERS_OUT;

	if (linesout)
		(void) printf("\n");

	printf(VOL_HDR_FMT, SET_HDR_TXT);

	if (dflags & FLAGS) {
		printf(STAT_HDR_FMT, TYPE_HDR_TXT);
		printf(STAT_HDR_FMT, STAT_HDR_TXT);
	}

	if (dflags & ASYNC_QUEUE)
		printf(STAT_HDR_FMT, QUEUE_HDR_TXT);

	if (dflags & PCTS)
		printf(PCT_HDR_FMT, PCT_HDR_TXT);

	printf(ROLE_HDR_FMT, ROLE_HDR_TXT);

	if (dflags & ASYNC_QUEUE) {
		printf(TPS_HDR_FMT, QUEUE_ITEMS_TXT);
		printf(KPS_HDR_FMT, QUEUE_KBYTES_TXT);
		printf(TPS_HDR_FMT, QUEUE_ITEMS_HW_TXT);
		printf(KPS_HDR_FMT, QUEUE_KBYTES_HW_TXT);
	}

	if (dflags & SUMMARY) {
		if ((mode & MULTI) && (mode & SDBC)) {
			printf(KPS_HDR_FMT, CKPS_HDR_TXT);
			printf(KPS_HDR_FMT, DKPS_HDR_TXT);
		} else
			printf(KPS_HDR_FMT, KPS_HDR_TXT);
		printf(TPS_HDR_FMT, TPS_HDR_TXT);
		printf(SVT_HDR_FMT, SVT_HDR_TXT);

		printf("\n");

		return;
	}

	if (dflags & READ) {
		if ((mode & MULTI) && (mode & SDBC)) {
			printf(KPS_HDR_FMT, CRKPS_HDR_TXT);
			printf(KPS_HDR_FMT, DRKPS_HDR_TXT);
		} else
			printf(KPS_HDR_FMT, RKPS_HDR_TXT);

		printf(TPS_HDR_FMT, RTPS_HDR_TXT);
	}

	if (dflags & WRITE) {
		if ((mode & MULTI) && (mode & SDBC)) {
			printf(KPS_HDR_FMT, CWKPS_HDR_TXT);
			printf(KPS_HDR_FMT, DWKPS_HDR_TXT);
		} else
			printf(KPS_HDR_FMT, WKPS_HDR_TXT);

		printf(TPS_HDR_FMT, WTPS_HDR_TXT);
	}

	if (dflags & TIMING)
		printf(SVT_HDR_FMT, SVT_HDR_TXT);

	(void) printf("\n");
}
