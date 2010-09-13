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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>

#include <inj_event.h>
#include <inj_err.h>

#include <fm/fmd_log.h>

typedef struct inj_logfile {
	uint64_t ilf_sec;	/* timestamp seconds from previous record */
	uint64_t ilf_nsec;	/* timestamp nanoseconds from previous record */
	int ilf_index;		/* record index in log file for fake lineno */
} inj_logfile_t;

/*ARGSUSED*/
static int
inj_logfile_event(fmd_log_t *lp, const fmd_log_record_t *rp, void *data)
{
	inj_cmd_t *cmd = inj_zalloc(sizeof (inj_cmd_t));
	inj_defn_t *ev = inj_zalloc(sizeof (inj_defn_t));

	hrtime_t rec_sec = rp->rec_sec + rp->rec_nsec / NANOSEC;
	hrtime_t rec_nsec = rp->rec_nsec % NANOSEC;

	inj_logfile_t *ilf = data;
	hrtime_t delta;

	if (ilf->ilf_index == 1)
		goto add_event; /* do not try to adjust time for first record */

	/*
	 * If the current record's time is before that of the previous record,
	 * advance it to the previous record time.  This may occur when delays
	 * between capturing ENA and enqueuing a sysevent are observed.
	 */
	if (rec_sec < ilf->ilf_sec ||
	    (rec_sec == ilf->ilf_sec && rec_nsec < ilf->ilf_nsec)) {
		warn("record [%d] (%s) timestamp is out of order: "
		    "advancing event time to %llx.%llx\n",
		    ilf->ilf_index, rp->rec_class, ilf->ilf_sec, ilf->ilf_nsec);
		rec_sec = ilf->ilf_sec;
		rec_nsec = ilf->ilf_nsec;
	}

	/*
	 * For now, compute the delta between the previous record and this one
	 * as a number of nanoseconds and advance the clock.  If a massively
	 * large delay is observed (>INT64_MAX ns), we abort.  This could be
	 * improved if necessary by sending more than one cmd_addhrt in a loop.
	 */
	delta = (rec_sec - ilf->ilf_sec) * NANOSEC;
	delta += (hrtime_t)rec_nsec - (hrtime_t)ilf->ilf_nsec;

	if (delta < 0)
		die("record [%d] timestamp delta too large\n", ilf->ilf_index);

	if (delta > 0)
		inj_cmds_add(inj_cmd_addhrt(delta));

add_event:
	ev->defn_name = inj_strdup(rp->rec_class);
	ev->defn_lineno = ilf->ilf_index++;

	if ((errno = nvlist_dup(rp->rec_nvl, &ev->defn_nvl, 0)) != 0)
		die("failed to allocate nvl for %s event", rp->rec_class);

	cmd->cmd_type = CMD_SEND_EVENT;
	cmd->cmd_event = ev;

	inj_cmds_add(cmd);

	ilf->ilf_sec = rec_sec;
	ilf->ilf_nsec = rec_nsec;

	return (0);
}

inj_list_t *
inj_logfile_read(fmd_log_t *lp)
{
	const char *label = fmd_log_label(lp);
	inj_logfile_t ilf;

	if (strcmp(label, "error") != 0)
		die("cannot use '%s' log as injector input\n", label);

	bzero(&ilf, sizeof (ilf));
	ilf.ilf_index = 1;

	if (fmd_log_iter(lp, inj_logfile_event, &ilf) != 0) {
		die("failed to process log: %s\n",
		    fmd_log_errmsg(lp, fmd_log_errno(lp)));
	}

	return (inj_cmds_get());
}
