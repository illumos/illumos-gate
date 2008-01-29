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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of the "scan file" interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include "vs_incl.h"

/* local functions */
static void vs_svc_vlog(char *, vs_result_t *);
static void vs_svc_audit(char *, vs_result_t *);

/*
 * vs_svc_init, vs_svc_fini
 *
 * Invoked on daemon load and unload
 */
void
vs_svc_init()
{
}

void
vs_svc_fini()
{
}


/*
 * vs_svc_scan_file
 *
 * vs_svc_scan_file is responsible for:
 *  - determining if a scan is required
 *  - obtaining & releasing a scan engine connection
 *  - invoking the scan engine interface code to do the scan
 *  - retrying a failed scan (up to VS_MAX_RETRY times)
 *  - updating scan statistics
 *  - logging virus information
 *
 *
 * Returns:
 *  VS_STATUS_NO_SCAN - scan not reqd, or daemon shutting down
 *  VS_STATUS_CLEAN - scan success. File clean.
 *                    new scanstamp returned in scanstamp param.
 *  VS_STATUS_INFECTED - scan success. File infected.
 *  VS_STATUS_ERROR - scan failure either in vscand or scan engine.
 */
int
vs_svc_scan_file(char *devname, char *fname, vs_attr_t *fattr, int flags,
    vs_scanstamp_t *scanstamp)
{
	vs_eng_conn_t conn;
	int retries;
	vs_result_t result;

	/* initialize response scanstamp to current scanstamp value */
	(void) strlcpy(*scanstamp, fattr->vsa_scanstamp,
	    sizeof (vs_scanstamp_t));


	/* No scan if file quarantined */
	if (fattr->vsa_quarantined)
		return (VS_STATUS_NO_SCAN);

	/* No scan if file not modified AND scanstamp is current */
	if ((fattr->vsa_modified == 0) &&
	    vs_eng_scanstamp_current(fattr->vsa_scanstamp)) {
		return (VS_STATUS_NO_SCAN);
	}

	(void) memset(&result, 0, sizeof (vs_result_t));
	result.vsr_rc = VS_RESULT_UNDEFINED;

	for (retries = 0; retries <= VS_MAX_RETRY; retries++) {
		/* identify available engine connection */
		if (vs_eng_get(&conn, retries) != 0) {
			result.vsr_rc = VS_RESULT_ERROR;
			continue;
		}

		/* connect to engine and scan file */
		if (vs_eng_connect(&conn) != 0) {
			result.vsr_rc = VS_RESULT_SE_ERROR;
		} else {
			if (vscand_get_state() == VS_STATE_SHUTDOWN) {
				vs_eng_release(&conn);
				return (VS_STATUS_NO_SCAN);
			}

			(void) vs_icap_scan_file(&conn, devname, fname,
			    fattr->vsa_size, flags, &result);
		}

		/* if no error, clear error state on engine and break */
		if ((result.vsr_rc != VS_RESULT_SE_ERROR) &&
		    (result.vsr_rc != VS_RESULT_ERROR)) {
			vs_eng_set_error(&conn, 0);
			vs_eng_release(&conn);
			break;
		}

		/* treat error on shutdown as scan not required */
		if (vscand_get_state() == VS_STATE_SHUTDOWN) {
			vs_eng_release(&conn);
			return (VS_STATUS_NO_SCAN);
		}

		/* set engine's error state and update engine stats */
		if (result.vsr_rc == VS_RESULT_SE_ERROR) {
			vs_eng_set_error(&conn, 1);
			vs_stats_eng_err(conn.vsc_engid);
		}
		vs_eng_release(&conn);
	}

	vs_stats_set(result.vsr_rc);

	/*
	 * VS_RESULT_CLEANED - file infected, cleaned data available
	 * VS_RESULT_FORBIDDEN - file infected, no cleaned data
	 * Log virus, write audit record and return INFECTED status
	 */
	if (result.vsr_rc == VS_RESULT_CLEANED ||
	    result.vsr_rc == VS_RESULT_FORBIDDEN) {
		vs_svc_vlog(fname, &result);
		vs_svc_audit(fname, &result);
		return (VS_STATUS_INFECTED);
	}

	/* VS_RESULT_CLEAN - Set the scanstamp and return CLEAN status */
	if (result.vsr_rc == VS_RESULT_CLEAN) {
		(void) strlcpy(*scanstamp, result.vsr_scanstamp,
		    sizeof (vs_scanstamp_t));
		return (VS_STATUS_CLEAN);
	}

	return (VS_STATUS_ERROR);
}


/*
 * vs_svc_vlog
 *
 * log details of infections detected in file
 * If virus log is not configured  or cannot be opened, use syslog.
 */
static void
vs_svc_vlog(char *filepath, vs_result_t *result)
{
	FILE *fp = NULL;
	time_t sec;
	struct tm *timestamp;
	char timebuf[18]; /* MM/DD/YY hh:mm:ss */
	int i;
	char *log;

	if ((log = vscand_viruslog()) != NULL)
		fp = fopen(log, "a");

	if (fp) {
		(void) time(&sec);
		timestamp = localtime(&sec);
		(void) strftime(timebuf, sizeof (timebuf), "%D %T", timestamp);
	}

	if (result->vsr_nviolations == 0) {
		if (fp) {
			(void) fprintf(fp, "%s quarantine %s",
			    timebuf, filepath);
		} else {
			syslog(LOG_WARNING, "quarantine %s\n", filepath);
		}
	} else {
		for (i = 0; i < result->vsr_nviolations; i++) {
			if (fp) {
				(void) fprintf(fp, "%s quarantine %s %d - %s\n",
				    timebuf, filepath,
				    result->vsr_vrec[i].vr_id,
				    result->vsr_vrec[i].vr_desc);
			} else {
				syslog(LOG_WARNING, "quarantine %s %d - %s\n",
				    filepath,
				    result->vsr_vrec[i].vr_id,
				    result->vsr_vrec[i].vr_desc);
			}
		}
	}

	if (fp)
		(void) fclose(fp);
}


/*
 * vs_svc_audit
 *
 * Generate AUE_vscan_quarantine audit record containing name
 * of infected file, and violation details if available.
 */
static void
vs_svc_audit(char *filepath, vs_result_t *result)
{
	int i;
	char *violations[VS_MAX_VIOLATIONS];
	char data[VS_MAX_VIOLATIONS][VS_DESCRIPTION_MAX];
	adt_session_data_t *ah;
	adt_termid_t *p_tid;
	adt_event_data_t *event;

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA)) {
		syslog(LOG_AUTH | LOG_ALERT, "adt_start_session: %m");
		return;
	}

	if (adt_load_ttyname("/dev/console", &p_tid) != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_load_ttyname(/dev/console): %m");
		return;
	}

	if (adt_set_user(ah, ADT_NO_ATTRIB, ADT_NO_ATTRIB, ADT_NO_ATTRIB,
	    ADT_NO_ATTRIB, p_tid, ADT_NEW) != 0) {
		syslog(LOG_AUTH | LOG_ALERT, "adt_set_user(ADT_NO_ATTRIB): %m");
		(void) adt_end_session(ah);
		return;
	}

	if ((event = adt_alloc_event(ah, ADT_vscan_quarantine)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_alloc_event(ADT_vscan_quarantine)): %m");
		(void) adt_end_session(ah);
		return;
	}

	/* populate vscan audit event */
	event->adt_vscan_quarantine.file = filepath;
	for (i = 0; i < result->vsr_nviolations; i++) {
		(void) snprintf(data[i], VS_DESCRIPTION_MAX, "%d - %s",
		    result->vsr_vrec[i].vr_id, result->vsr_vrec[i].vr_desc);
		violations[i] = data[i];
	}

	event->adt_vscan_quarantine.violations = (char **)violations;
	event->adt_vscan_quarantine.nviolations = result->vsr_nviolations;

	if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS))
		syslog(LOG_AUTH | LOG_ALERT, "adt_put_event: %m");

	adt_free_event(event);
	(void) adt_end_session(ah);
}
