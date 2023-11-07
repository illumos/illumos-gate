/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strlog.h>

int
msgbuf(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	queue_t q;
	uintptr_t qp;
	mblk_t next;
	mblk_t cont;
	log_ctl_t lctl;
	char line[1024];
	uint_t verbose = FALSE;
	uint_t delta = FALSE;
	uint_t abstime = FALSE;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_readsym(&qp, sizeof (qp), "log_recentq") == -1) {
			mdb_warn("failed to read log_recent");
			return (DCMD_ERR);
		}

		if (mdb_vread(&q, sizeof (q), qp) == -1) {
			mdb_warn("failed to read queue_t at %p", qp);
			return (DCMD_ERR);
		}

		if (mdb_pwalk_dcmd("b_next", "msgbuf", argc, argv,
		    (uintptr_t)q.q_first) == -1) {
			mdb_warn("can't walk 'b_next'");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    't', MDB_OPT_SETBITS, TRUE, &delta,
	    'T', MDB_OPT_SETBITS, TRUE, &abstime,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	/* For backwards compatability, -v implies -T */
	if (verbose)
		abstime = TRUE;

	if (DCMD_HDRSPEC(flags)) {
		int amt = 80;

		mdb_printf("%<u>");
		if (abstime) {
			mdb_printf("%-20s ", "TIMESTAMP");
			amt -= 21;
		}
		if (delta) {
			mdb_printf("%-20s ", "DELTA");
			amt -= 21;
		}
		if (verbose) {
			mdb_printf("%?s ", "LOGCTL");
			amt -= 17;
		}
		mdb_printf("%-*s%</u>\n", amt, "MESSAGE");
	}

	if (mdb_vread(&next, sizeof (next), addr) == -1) {
		mdb_warn("failed to read msgb structure at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&lctl, sizeof (lctl), (uintptr_t)next.b_rptr) == -1) {
		mdb_warn("failed to read log_ctl_t at %p", next.b_rptr);
		return (DCMD_ERR);
	}

	if (mdb_vread(&cont, sizeof (cont), (uintptr_t)next.b_cont) == -1) {
		mdb_warn("failed to read msgb structure at %p", next.b_cont);
		return (DCMD_ERR);
	}

	if (mdb_readstr(line, sizeof (line), (uintptr_t)cont.b_rptr) == -1) {
		mdb_warn("failed to read string at %p", cont.b_rptr);
		return (DCMD_ERR);
	}

	if (abstime)
		mdb_printf("%Y ", lctl.ttime);

	if (delta) {
		timestruc_t	hr_time;
		int64_t		diff;
		char		buf[32] = { 0 };

		if (mdb_readvar(&hr_time, "panic_hrestime") == -1) {
			mdb_warn("failed to read panic_hrestime");
			return (DCMD_ERR);
		}

		if (hr_time.tv_sec == 0 &&
		    mdb_readvar(&hr_time, "hrestime") == -1) {
			mdb_warn("failed to read hrestime");
			return (DCMD_ERR);
		}

		diff = (int64_t)lctl.ttime - hr_time.tv_sec;
		mdb_nicetime(SEC2NSEC(diff), buf, sizeof (buf));
		mdb_printf("%-20s ", buf);
	}

	if (verbose)
		mdb_printf("%?p ", next.b_rptr);

	/* skip leading CR to avoid extra lines */
	if (line[0] == 0x0d)
		mdb_printf("%s", &line[1]);
	else
		mdb_printf("%s", &line[0]);

	return (DCMD_OK);
}

void
msgbuf_help(void)
{
	mdb_printf("Print the most recent console messages.\n\n"
	    "%<b>OPTIONS%</b>\n"
	    "\t-t\tInclude the age of the message from now.\n"
	    "\t-T\tInclude the date/time of the message.\n"
	    "\t-v\tInclude the date/time of the message as well as the address "
	    "of its log_ctl_t.\n");
}
