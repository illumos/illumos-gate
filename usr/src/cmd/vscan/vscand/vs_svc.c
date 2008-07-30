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
#include <pthread.h>

#include "vs_incl.h"

/*
 * vs_svc_nodes - table of scan requests and their thread id and
 * scan engine context.
 * The table is sized by the value passed to vs_svc_init. This
 * value is obtained from the kernel and represents the maximum
 * request idx that the kernel will request vscand to process.
 * The table is indexed by the vsr_idx value passed in
 * the scan request - always non-zero. This value is also the index
 * into the kernel scan request table and identifies the instance of
 * the driver being used to access file data for the scan. Although
 * this is of no consequence here, it is useful information for debug.
 *
 * When a scan request is received a response is sent indicating
 * one of the following:
 * VS_STATUS_ERROR - an error occurred
 * VS_STATUS_NO_SCAN - no scan is required
 * VS_STATUS_SCANNING - request has been queued for async processing
 *
 * If the scan is required (VS_STATUS_SCANNING) a thread is created
 * to perform the scan. It's tid is saved in vs_svc_nodes.
 *
 * In the case of SHUTDOWN, vs_terminate requests that all scan
 * engine connections be closed, thus termintaing any in-progress
 * scans, then awaits completion of all scanning threads as identified
 * in vs_svc_nodes.
 */

typedef struct vs_svc_node {
	pthread_t vsn_tid;
	vs_scan_req_t vsn_req;
	vs_eng_ctx_t vsn_eng;
} vs_svc_node_t;

static vs_svc_node_t *vs_svc_nodes;
static uint32_t vs_svc_max_node; /* max idx into vs_svc_nodes */
static pthread_mutex_t vs_svc_mutex = PTHREAD_MUTEX_INITIALIZER;


/* local functions */
static void *vs_svc_async_scan(void *);
static int vs_svc_scan_file(vs_svc_node_t *, vs_scanstamp_t *);
static void vs_svc_vlog(char *, vs_result_t *);
static void vs_svc_audit(char *, vs_result_t *);


/*
 * vs_svc_init, vs_svc_fini
 *
 * Invoked on daemon load and unload
 */
int
vs_svc_init(uint32_t max_req)
{
	vs_svc_max_node = max_req;
	vs_svc_nodes = (vs_svc_node_t *)
	    calloc(max_req + 1, sizeof (vs_svc_node_t));

	return (vs_svc_nodes == NULL ? -1 : 0);
}

void
vs_svc_fini()
{
	if (vs_svc_nodes)
		free(vs_svc_nodes);
}


/*
 * vs_svc_terminate
 *
 * Close all scan engine connections to terminate in-progress scan
 * requests, and wait for all threads in vs_svc_nodes to complete
 */
void
vs_svc_terminate()
{
	int i;
	pthread_t tid;

	/* close connections to abort requests */
	vs_eng_close_connections();

	/* wait for threads */
	for (i = 1; i <= vs_svc_max_node; i++) {

		(void) pthread_mutex_lock(&vs_svc_mutex);
		tid = vs_svc_nodes[i].vsn_tid;
		(void) pthread_mutex_unlock(&vs_svc_mutex);

		if (tid != 0)
			(void) pthread_join(tid, NULL);
	}
}


/*
 * vs_svc_queue_scan_req
 *
 * Determine if the file needs to be scanned - either it has
 * been modified or its scanstamp is not current.
 * Initiate a thread to process the request, saving the tid
 * in vs_svc_nodes[idx].vsn_tid, where idx is the vsr_idx passed in
 * the scan request.
 *
 * Returns: VS_STATUS_ERROR - error
 *          VS_STATUS_NO_SCAN - no scan required
 *          VS_STATUS_SCANNING - async scan initiated
 */
int
vs_svc_queue_scan_req(vs_scan_req_t *req)
{
	pthread_t tid;
	vs_svc_node_t *node;

	/* No scan if file quarantined */
	if (req->vsr_quarantined)
		return (VS_STATUS_NO_SCAN);

	/* No scan if file not modified AND scanstamp is current */
	if ((req->vsr_modified == 0) &&
	    vs_eng_scanstamp_current(req->vsr_scanstamp)) {
		return (VS_STATUS_NO_SCAN);
	}

	/* scan required */
	node = &(vs_svc_nodes[req->vsr_idx]);

	(void) pthread_mutex_lock(&vs_svc_mutex);
	if ((node->vsn_tid != 0) || (req->vsr_idx > vs_svc_max_node)) {
		(void) pthread_mutex_unlock(&vs_svc_mutex);
		return (VS_STATUS_ERROR);
	}

	node->vsn_req = *req;

	if (pthread_create(&tid, NULL, vs_svc_async_scan, (void *)node) != 0) {
		(void) pthread_mutex_unlock(&vs_svc_mutex);
		return (VS_STATUS_ERROR);
	}

	node->vsn_tid = tid;
	(void) pthread_mutex_unlock(&vs_svc_mutex);

	return (VS_STATUS_SCANNING);
}


/*
 * vs_svc_async_scan
 *
 * Initialize response structure, invoke vs_svc_scan_file to
 * perform the scan, then send the result to the kernel.
 */
static void *
vs_svc_async_scan(void *arg)
{
	vs_svc_node_t *node = (vs_svc_node_t *)arg;
	vs_scan_req_t *scan_req = &(node->vsn_req);
	vs_scan_rsp_t scan_rsp;

	scan_rsp.vsr_idx = scan_req->vsr_idx;
	scan_rsp.vsr_seqnum = scan_req->vsr_seqnum;
	scan_rsp.vsr_result = vs_svc_scan_file(node, &scan_rsp.vsr_scanstamp);

	/* clear node and send async response to kernel */
	(void) pthread_mutex_lock(&vs_svc_mutex);
	(void) memset(node, 0, sizeof (vs_svc_node_t));
	(void) pthread_mutex_unlock(&vs_svc_mutex);

	(void) vscand_kernel_result(&scan_rsp);

	return (NULL);
}


/*
 * vs_svc_scan_file
 *
 * vs_svc_scan_file is responsible for:
 *  - obtaining & releasing a scan engine connection
 *  - invoking the scan engine interface code to do the scan
 *  - retrying a failed scan (up to VS_MAX_RETRY times)
 *  - updating scan statistics
 *  - logging virus information
 *
 *
 * Returns:
 *  VS_STATUS_NO_SCAN - scan not reqd; daemon shutting down
 *  VS_STATUS_CLEAN - scan success. File clean.
 *                    new scanstamp returned in scanstamp param.
 *  VS_STATUS_INFECTED - scan success. File infected.
 *  VS_STATUS_ERROR - scan failure either in vscand or scan engine.
 */
static int
vs_svc_scan_file(vs_svc_node_t *node, vs_scanstamp_t *scanstamp)
{
	char devname[MAXPATHLEN];
	int flags = 0;
	int retries;
	vs_result_t result;
	vs_scan_req_t *req = &(node->vsn_req);
	vs_eng_ctx_t *eng = &(node->vsn_eng);

	(void) snprintf(devname, MAXPATHLEN, "%s%d", VS_DRV_PATH, req->vsr_idx);

	/* initialize response scanstamp to current scanstamp value */
	(void) strlcpy(*scanstamp, req->vsr_scanstamp, sizeof (vs_scanstamp_t));

	(void) memset(&result, 0, sizeof (vs_result_t));
	result.vsr_rc = VS_RESULT_UNDEFINED;

	for (retries = 0; retries <= VS_MAX_RETRY; retries++) {
		/* get engine connection */
		if (vs_eng_get(eng, (retries != 0)) != 0) {
			result.vsr_rc = VS_RESULT_ERROR;
			continue;
		}

		/* shutdown could occur while waiting for engine connection */
		if (vscand_get_state() == VS_STATE_SHUTDOWN) {
			vs_eng_release(eng);
			return (VS_STATUS_NO_SCAN);
		}

		/* scan file */
		(void) vs_icap_scan_file(eng, devname, req->vsr_path,
		    req->vsr_size, flags, &result);

		/* if no error, clear error state on engine and break */
		if ((result.vsr_rc != VS_RESULT_SE_ERROR) &&
		    (result.vsr_rc != VS_RESULT_ERROR)) {
			vs_eng_set_error(eng, 0);
			vs_eng_release(eng);
			break;
		}

		/* treat error on shutdown as scan not required */
		if (vscand_get_state() == VS_STATE_SHUTDOWN) {
			vs_eng_release(eng);
			return (VS_STATUS_NO_SCAN);
		}

		/* set engine's error state and update engine stats */
		if (result.vsr_rc == VS_RESULT_SE_ERROR)
			vs_eng_set_error(eng, 1);

		vs_eng_release(eng);
	}

	vs_stats_set(result.vsr_rc);

	/*
	 * VS_RESULT_CLEANED - file infected, cleaned data available
	 * VS_RESULT_FORBIDDEN - file infected, no cleaned data
	 * Log virus, write audit record and return INFECTED status
	 */
	if (result.vsr_rc == VS_RESULT_CLEANED ||
	    result.vsr_rc == VS_RESULT_FORBIDDEN) {
		vs_svc_vlog(req->vsr_path, &result);
		vs_svc_audit(req->vsr_path, &result);
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
 * log details of infections detected in syslig
 * If virus log is configured log details there too
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

	/* syslog */
	if (result->vsr_nviolations == 0) {
		syslog(LOG_NOTICE, "quarantine %s\n", filepath);
	} else {
		for (i = 0; i < result->vsr_nviolations; i++) {
			syslog(LOG_NOTICE, "quarantine %s %d - %s\n",
			    filepath,
			    result->vsr_vrec[i].vr_id,
			    result->vsr_vrec[i].vr_desc);
		}
	}

	/* log file */
	if (((log = vscand_viruslog()) == NULL) ||
	    ((fp = fopen(log, "a")) == NULL)) {
		return;
	}

	(void) time(&sec);
	timestamp = localtime(&sec);
	(void) strftime(timebuf, sizeof (timebuf), "%D %T", timestamp);

	if (result->vsr_nviolations == 0) {
		(void) fprintf(fp, "%s quarantine %d[%s]\n",
		    timebuf, strlen(filepath), filepath);
	} else {
		for (i = 0; i < result->vsr_nviolations; i++) {
			(void) fprintf(fp, "%s quarantine %d[%s] %d - %d[%s]\n",
			    timebuf, strlen(filepath), filepath,
			    result->vsr_vrec[i].vr_id,
			    strlen(result->vsr_vrec[i].vr_desc),
			    result->vsr_vrec[i].vr_desc);
		}
	}

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
