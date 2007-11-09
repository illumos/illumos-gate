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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
static int  vs_svc_process_scan_result(vs_attr_t *, vs_result_t *);
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
 * Returns:
 *  VS_ACCESS_ALLOW, VS_ACCESS_DENY
 */
int
vs_svc_scan_file(char *devname, char *fname, vs_attr_t *fattr, int flags)
{
	vs_eng_conn_t conn;
	int access = VS_ACCESS_UNDEFINED;
	int rc, retries;
	vs_result_t result;

	/* deny access to quarantined files */
	if (fattr->vsa_quarantined)
		return (VS_ACCESS_DENY);

	/* allow access if not modified & scanstamp current */
	if ((fattr->vsa_modified  == 0) &&
	    vs_eng_scanstamp_current(fattr->vsa_scanstamp)) {
		return (VS_ACCESS_ALLOW);
	}

	(void) memset(&result, 0, sizeof (vs_result_t));
	result.vsr_rc = VS_RESULT_UNDEFINED;

	for (retries = 0; retries <= VS_MAX_RETRY; retries++) {
		/* identify available engine connection */
		if (vs_eng_get(&conn, retries) != 0) {
			rc = VS_RESULT_ERROR;
			continue;
		}

		/* connect to engine and scan file */
		if (vs_eng_connect(&conn) != 0)
			rc = VS_RESULT_SE_ERROR;
		else {
			if (vscand_get_state() == VS_STATE_SHUTDOWN) {
				vs_eng_release(&conn);
				return (VS_ACCESS_ALLOW);
			}

			rc = vs_icap_scan_file(&conn, devname, fname,
			    fattr->vsa_size, flags, &result);
		}

		/* if no error, clear error state on engine and break */
		if ((rc != VS_RESULT_SE_ERROR) && (rc != VS_RESULT_ERROR)) {
			vs_eng_set_error(&conn, 0);
			vs_eng_release(&conn);
			break;
		}

		/* if scan failed due to shutdown, allow access */
		if (vscand_get_state() == VS_STATE_SHUTDOWN) {
			vs_eng_release(&conn);
			return (VS_ACCESS_ALLOW);
		}

		/* set engine's error state and update engine stats */
		if (rc == VS_RESULT_SE_ERROR) {
			vs_eng_set_error(&conn, 1);
			vs_stats_eng_err(conn.vsc_engid);
		}
		vs_eng_release(&conn);
	}

	vs_stats_set(rc);

	/* if file infected, update virus log and write audit record */
	if (result.vsr_rc == VS_RESULT_CLEANED ||
	    result.vsr_rc == VS_RESULT_FORBIDDEN) {
		vs_svc_vlog(fname, &result);
		vs_svc_audit(fname, &result);
	}

	access = vs_svc_process_scan_result(fattr, &result);

	return (access);
}


/*
 * vs_svc_process_scan_result
 *
 * Translate the scan result into VS_ACCESS_ALLOW or VS_ACCESS_DENY.
 * If the scan failed (VS_RESULT_ERROR) deny access if the
 * scan was initiated because the file had been modified or
 * had never been scanned. Otherwise allow access.
 *
 *   If file has been modified or has never been scanned, it must
 *   be successfully scanned before access is allowed
 *
 *   If the file has previously been scanned and has not been
 *   modified, don't deny access if scan fail, only if the file
 *   is found to be infected.
 *
 * If the file is still infected set quarantine attribute,
 * otherwise clear modified attribute.
 *
 * Returns: VS_ACCESS_ALLOW, VS_ACCESS_DENY
 */
static int
vs_svc_process_scan_result(vs_attr_t *fattr, vs_result_t *result)
{
	int access = VS_ACCESS_DENY;

	switch (result->vsr_rc) {
	case VS_RESULT_CLEANED:
	case VS_RESULT_FORBIDDEN:
		fattr->vsa_scanstamp[0] = '\0';
		fattr->vsa_quarantined = 1;
		access = VS_ACCESS_DENY;
		break;
	case VS_RESULT_CLEAN:
		(void) strlcpy(fattr->vsa_scanstamp, result->vsr_scanstamp,
		    sizeof (vs_scanstamp_t));
		fattr->vsa_modified = 0;
		access = VS_ACCESS_ALLOW;
		break;
	case VS_RESULT_ERROR:
	case VS_RESULT_SE_ERROR:
	case VS_RESULT_UNDEFINED:
	default:
		if ((fattr->vsa_modified) || (fattr->vsa_scanstamp[0] == '\0'))
			access = VS_ACCESS_DENY;
		else
			access = VS_ACCESS_ALLOW;
		break;
	}

	return (access);
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
