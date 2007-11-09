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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/door.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h> /* for string functions */
#include <sys/vscan.h>


static int vscan_door_id = -1;
static door_handle_t vscan_door_handle = NULL;
static kmutex_t vscan_door_mutex;
static kcondvar_t vscan_door_cv;
static int vscan_door_call_count = 0;


/*
 * vscan_door_init
 */
int
vscan_door_init(void)
{
	mutex_init(&vscan_door_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&vscan_door_cv, NULL, CV_DEFAULT, NULL);
	return (0);
}


/*
 * vscan_door_fini
 */
void
vscan_door_fini(void)
{
	mutex_destroy(&vscan_door_mutex);
	cv_destroy(&vscan_door_cv);
}


/*
 * vscan_door_open
 */
int
vscan_door_open(int door_id)
{
	mutex_enter(&vscan_door_mutex);

	if (vscan_door_handle == NULL) {
		vscan_door_id = door_id;
		vscan_door_handle = door_ki_lookup(door_id);
	}

	mutex_exit(&vscan_door_mutex);

	if (vscan_door_handle == NULL) {
		cmn_err(CE_WARN, "Internal communication error "
		    "- failed to access vscan service daemon.");
		return (-1);
	}

	return (0);
}


/*
 * vscan_door_close
 */
void
vscan_door_close(void)
{
	mutex_enter(&vscan_door_mutex);

	/* wait for any in-progress requests to complete */
	while (vscan_door_call_count > 0) {
		cv_wait(&vscan_door_cv, &vscan_door_mutex);
	}

	if (vscan_door_handle) {
		door_ki_rele(vscan_door_handle);
		vscan_door_handle = NULL;
	}

	mutex_exit(&vscan_door_mutex);
}


/*
 * vscan_door_scan_file
 */
int
vscan_door_scan_file(vs_scan_req_t *scan_req)
{
	int err, rc = 0;
	door_arg_t arg;

	if (!vscan_door_handle &&
	    vscan_door_open(vscan_door_id) != 0)
		return (-1);

	mutex_enter(&vscan_door_mutex);
	vscan_door_call_count++;
	mutex_exit(&vscan_door_mutex);

	arg.data_ptr = (char *)scan_req;
	arg.data_size = sizeof (vs_scan_req_t);
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = (char *)scan_req;
	arg.rsize = sizeof (vs_scan_req_t);

	if ((err = door_ki_upcall(vscan_door_handle, &arg)) != 0) {
		cmn_err(CE_WARN, "Internal communication error (%d)"
		    "- failed to send scan request to vscand", err);
		vscan_door_close();
		rc = -1;
	}

	mutex_enter(&vscan_door_mutex);
	vscan_door_call_count--;
	cv_signal(&vscan_door_cv);
	mutex_exit(&vscan_door_mutex);

	return (rc);
}
