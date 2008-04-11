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
 * Implementation of the vscan statistics interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <door.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "vs_incl.h"


/* local data */
static vs_stats_t vscan_stats;
static int vs_stats_door_cookie;
static int vs_stats_door_fd = -1;
static pthread_mutex_t vs_stats_mutex = PTHREAD_MUTEX_INITIALIZER;


/* function prototype */
static int vs_stats_check_auth(void);
static void vs_stats_reset(void);
static void vs_stats_door_call(void *, char *, size_t, door_desc_t *, uint_t);


/*
 * vs_stats_init
 *
 * Invoked on daemon load and unload
 */
int
vs_stats_init(void)
{
	(void) pthread_mutex_lock(&vs_stats_mutex);

	(void) memset(&vscan_stats, 0, sizeof (vs_stats_t));

	/* door initialization */
	if ((vs_stats_door_fd = door_create(vs_stats_door_call,
	    &vs_stats_door_cookie, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		vs_stats_door_fd = -1;
	} else {
		(void) fdetach(VS_STATS_DOOR_NAME);
		if (fattach(vs_stats_door_fd, VS_STATS_DOOR_NAME) < 0) {
			(void) door_revoke(vs_stats_door_fd);
			vs_stats_door_fd = -1;
		}
	}

	(void) pthread_mutex_unlock(&vs_stats_mutex);

	return ((vs_stats_door_fd == -1) ? -1 : 0);
}


/*
 * vs_stats_fini
 *
 * Invoked on daemon unload
 */
void
vs_stats_fini(void)
{
	(void) pthread_mutex_lock(&vs_stats_mutex);

	/* door termination */
	if (vs_stats_door_fd != -1)
		(void) door_revoke(vs_stats_door_fd);
	vs_stats_door_fd = -1;

	(void) fdetach(VS_STATS_DOOR_NAME);
	(void) unlink(VS_STATS_DOOR_NAME);

	(void) pthread_mutex_unlock(&vs_stats_mutex);
}


/*
 * vs_stats_check_auth
 *
 * Returns: 0 caller authorized to reset stats
 *         -1 caller not authorized to reset stats
 */
static int
vs_stats_check_auth()
{
	ucred_t *uc = NULL;
	uid_t uid;
	struct passwd *pw;

	if (door_ucred(&uc) != 0)
		return (-1);

	if (((uid = ucred_getsuid(uc)) == (uid_t)-1) ||
	    ((pw = getpwuid(uid)) == NULL) ||
	    (chkauthattr(VS_VALUE_AUTH, pw->pw_name) != 1)) {
		ucred_free(uc);
		return (-1);
	}

	ucred_free(uc);
	return (0);
}


/*
 * vs_stats_door_call
 */
/* ARGSUSED */
static void
vs_stats_door_call(void *cookie, char *ptr, size_t size, door_desc_t *dp,
		uint_t n_desc)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	vs_stats_req_t *req = (vs_stats_req_t *)ptr;
	vs_stats_rsp_t rsp;

	if ((cookie != &vs_stats_door_cookie) ||
	    (ptr == NULL) ||
	    (size != sizeof (vs_stats_req_t)) ||
	    (req->vsr_magic != VS_STATS_DOOR_MAGIC)) {
		return;
	}

	rsp.vsr_magic = VS_STATS_DOOR_MAGIC;

	switch (req->vsr_id) {
	case VS_STATS_GET:
		(void) pthread_mutex_lock(&vs_stats_mutex);
		rsp.vsr_stats = vscan_stats;
		(void) pthread_mutex_unlock(&vs_stats_mutex);
		(void) door_return((char *)&rsp, sizeof (vs_stats_rsp_t),
		    NULL, 0);
		break;

	case VS_STATS_RESET:
		vs_stats_reset();
		(void) door_return(NULL, 0, NULL, 0);
		break;

	default:
		return;
	}
}


/*
 * vs_stats_reset
 *
 * Reset totals and per-engine statistics to 0
 */
static void
vs_stats_reset()
{
	int i;

	if (vs_stats_check_auth() != 0)
		return;

	(void) pthread_mutex_lock(&vs_stats_mutex);

	vscan_stats.vss_scanned = 0;
	vscan_stats.vss_infected = 0;
	vscan_stats.vss_cleaned = 0;
	vscan_stats.vss_failed = 0;

	for (i = 0; i < VS_SE_MAX; i++)
		vscan_stats.vss_eng[i].vss_errors = 0;

	(void) pthread_mutex_unlock(&vs_stats_mutex);
}


/*
 * vs_stats_set
 *
 * Update scan request stats
 */
void
vs_stats_set(int retval)
{
	(void) pthread_mutex_lock(&vs_stats_mutex);

	switch (retval) {
	case VS_RESULT_CLEAN:
		vscan_stats.vss_scanned++;
		break;
	case VS_RESULT_CLEANED:
		vscan_stats.vss_scanned++;
		vscan_stats.vss_infected++;
		vscan_stats.vss_cleaned++;
		break;
	case VS_RESULT_FORBIDDEN:
		vscan_stats.vss_scanned++;
		vscan_stats.vss_infected++;
		break;
	case VS_RESULT_SE_ERROR:
	case VS_RESULT_ERROR:
	default:
		vscan_stats.vss_failed++;
		break;
	}

	(void) pthread_mutex_unlock(&vs_stats_mutex);
}


/*
 * vs_stats_eng_err
 *
 * Increment the error count stat for eng
 */
void
vs_stats_eng_err(char *engid)
{
	int i;

	(void) pthread_mutex_lock(&vs_stats_mutex);

	for (i = 0; i < VS_SE_MAX; i++) {
		if (*(vscan_stats.vss_eng[i].vss_engid) == 0)
			break;

		if (strcmp(vscan_stats.vss_eng[i].vss_engid, engid) == 0) {
			++(vscan_stats.vss_eng[i].vss_errors);
			break;
		}
	}

	(void) pthread_mutex_unlock(&vs_stats_mutex);
}


/*
 * vs_stats_config
 */
void
vs_stats_config(vs_props_all_t *config)
{
	int i, j;
	char *engid, *previd;
	vs_stats_t prev;

	(void) pthread_mutex_lock(&vs_stats_mutex);

	(void) memcpy(&prev, &vscan_stats, sizeof (vs_stats_t));
	(void) memset(&vscan_stats.vss_eng, 0, sizeof (vscan_stats.vss_eng));

	for (i = 0; i < VS_SE_MAX; i++) {
		engid = config->va_se[i].vep_engid;
		if (*engid == 0)
			break;

		(void) strlcpy(vscan_stats.vss_eng[i].vss_engid, engid,
		    VS_SE_NAME_LEN);

		/* find previous error count for engid */
		for (j = 0; j < VS_SE_MAX; j++) {
			previd = prev.vss_eng[j].vss_engid;
			if (strcmp(previd, engid) == 0) {
				vscan_stats.vss_eng[i].vss_errors =
				    prev.vss_eng[j].vss_errors;
				break;
			}
		}
	}

	(void) pthread_mutex_unlock(&vs_stats_mutex);
}
