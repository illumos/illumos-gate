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
 * vscand door server
 */

#include <door.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <varargs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pthread.h>
#include "vs_incl.h"

#define	VS_DOOR_VERSION	1
static int vs_door_cookie;

/* function prototype */
static void vs_door_scan_req(void *, char *, size_t, door_desc_t *, uint_t);

/* local data */
static int vs_door_fd = -1;
static pthread_mutex_t vs_door_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * vs_door_init
 *
 * Start the vscand door service.
 * Returns 0 on success. Otherwise, -1.
 */
int
vs_door_init(void)
{
	(void) pthread_mutex_lock(&vs_door_mutex);

	if ((vs_door_fd = door_create(vs_door_scan_req,
	    &vs_door_cookie, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		syslog(LOG_ERR, "vscand: door create%s", strerror(errno));
		vs_door_fd = -1;
	}

	(void) pthread_mutex_unlock(&vs_door_mutex);
	return (vs_door_fd);
}


/*
 * vscan_door_fini
 *
 * Stop the vscand door service.
 */
void
vs_door_fini(void)
{
	(void) pthread_mutex_lock(&vs_door_mutex);

	if (vs_door_fd >= 0) {
		if (door_revoke(vs_door_fd) < 0)
			syslog(LOG_ERR, "vscand: door revoke %s",
			    strerror(errno));
	}

	vs_door_fd = -1;

	(void) pthread_mutex_unlock(&vs_door_mutex);
}


/*
 * vs_door_scan_req
 *
 * Invoke the vscand door service.
 */
/* ARGSUSED */
static void
vs_door_scan_req(void *cookie, char *ptr, size_t size, door_desc_t *dp,
    uint_t n_desc)
{
	int flags = 0, access = VS_ACCESS_DENY;
	vs_scan_req_t scan_rsp;
	/* LINTED E_BAD_PTR_CAST_ALIGN - to be fixed with encoding */
	vs_scan_req_t *scan_req = (vs_scan_req_t *)ptr;
	char *fname = scan_req->vsr_path;
	char devname[MAXPATHLEN];
	uint64_t fsize = scan_req->vsr_size;
	vs_attr_t fattr;

	(void) snprintf(devname, MAXPATHLEN, "%s%d",
	    VS_DRV_PATH, scan_req->vsr_id);
	fattr.vsa_size = fsize;
	fattr.vsa_modified = scan_req->vsr_modified;
	fattr.vsa_quarantined = scan_req->vsr_quarantined;
	(void) strlcpy(fattr.vsa_scanstamp, scan_req->vsr_scanstamp,
	    sizeof (vs_scanstamp_t));

	access = vs_svc_scan_file(devname, fname, &fattr, flags);

	/* process result */
	scan_rsp.vsr_access = access;
	scan_rsp.vsr_modified = fattr.vsa_modified;
	scan_rsp.vsr_quarantined = fattr.vsa_quarantined;
	(void) strlcpy(scan_rsp.vsr_scanstamp, fattr.vsa_scanstamp,
	    sizeof (vs_scanstamp_t));

	(void) door_return((char *)&scan_rsp, sizeof (vs_scan_req_t), NULL, 0);
}
