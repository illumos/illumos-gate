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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <libdlpi.h>
#include <libnwam.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include "events.h"
#include "ncp.h"
#include "ncu.h"
#include "objects.h"
#include "util.h"

/*
 * dlpi_events.c - this file contains routines to retrieve
 * DL_NOTE_LINK_[UP|DOWN] events from the system and packages them for high
 * level processing.  Holding a dlpi_handle to a link prevents the
 * associated driver unloading that can happen when IP is not plumbed,
 * so it is vital to ensure that the handle is open for the lifetime
 * of the WiFi connection.
 */

/*
 * This is a callback function executed when dlpi_recv() gets a DL_NOTE_LINK_UP.
 * It packages up the event for consumption by the link state machine.
 */
/* ARGSUSED0 */
static void
nwamd_dlpi_notify(dlpi_handle_t dhp, dlpi_notifyinfo_t *info, void *arg)
{
	nwamd_event_t ev;
	char *name = arg;

	if (info->dni_note & DL_NOTE_LINK_UP)
		ev = nwamd_event_init_link_state(name, B_TRUE);
	else
		ev = nwamd_event_init_link_state(name, B_FALSE);
	if (ev != NULL)
		nwamd_event_enqueue(ev);
}

/*
 * We are only intested in DL_NOTE_LINK_UP events which we've registered for
 * in nwamd_dlpi_add_link().  But we have to keep calling dlpi_recv() to
 * force the notification callback to be executed.
 */
static void *
nwamd_dlpi_thread(void *arg)
{
	int rc;
	dlpi_handle_t *dh = arg;

	do {
		rc = dlpi_recv(*dh, NULL, NULL, NULL, NULL, -1, NULL);
	} while (rc == DLPI_SUCCESS);
	nlog(LOG_ERR, "dlpi_recv failed: %s", dlpi_strerror(rc));
	return (NULL);
}

/*
 * This is called when we want to start receiving notifications from state
 * changes on a link.
 */
void
nwamd_dlpi_add_link(nwamd_object_t obj)
{
	nwamd_ncu_t *ncu = obj->nwamd_object_data;
	nwamd_link_t *link;
	dlpi_notifyid_t id;
	int rc;

	nlog(LOG_DEBUG, "nwamd_dlpi_add_link: ncu %p (%s) type %d",
	    ncu, obj->nwamd_object_name, ncu != NULL ? ncu->ncu_type : -1);

	assert(ncu != NULL && ncu->ncu_type == NWAM_NCU_TYPE_LINK);

	link = &ncu->ncu_node.u_link;

	/* Already running? */
	if (link->nwamd_link_dlpi_thread != 0) {
		nlog(LOG_DEBUG, "nwamd_dlpi_add_link(%s) already running",
		    obj->nwamd_object_name);
		return;
	}

	rc = dlpi_open(ncu->ncu_name, &link->nwamd_link_dhp, 0);
	if (rc != DLPI_SUCCESS) {
		nlog(LOG_ERR, "nwamd_dlpi_add_link: dlpi_open(%s) = %s",
		    ncu->ncu_name, dlpi_strerror(rc));
		return;
	}

	nwamd_set_unset_link_properties(ncu, B_TRUE);

	rc = dlpi_enabnotify(link->nwamd_link_dhp,
	    DL_NOTE_LINK_UP | DL_NOTE_LINK_DOWN, nwamd_dlpi_notify,
	    ncu->ncu_name, &id);
	if (rc != DLPI_SUCCESS) {
		nlog(LOG_ERR,
		    "nwamd_dlpi_add_link: dlpi_enabnotify(%s) = %s",
		    obj->nwamd_object_name, dlpi_strerror(rc));
		dlpi_close(link->nwamd_link_dhp);
		return;
	}

	rc = pthread_create(&link->nwamd_link_dlpi_thread, NULL,
	    nwamd_dlpi_thread, &link->nwamd_link_dhp);
	if (rc != 0) {
		nlog(LOG_ERR, "nwamd_dlpi_add_link: couldn't create "
		    "dlpi thread for %s: %s", obj->nwamd_object_name,
		    strerror(rc));
		dlpi_close(link->nwamd_link_dhp);
	}
}

/*
 * This function is called when we are no longer interested in receiving
 * notification from state changes on a link.
 */
void
nwamd_dlpi_delete_link(nwamd_object_t obj)
{
	nwamd_ncu_t *ncu = obj->nwamd_object_data;

	nlog(LOG_DEBUG, "nwamd_dlpi_delete_link: ncu %p (%s) type %d",
	    ncu, obj->nwamd_object_name, ncu != NULL ? ncu->ncu_type : -1);

	if (ncu->ncu_node.u_link.nwamd_link_dlpi_thread != 0) {
		(void) pthread_cancel(
		    ncu->ncu_node.u_link.nwamd_link_dlpi_thread);
		(void) pthread_join(ncu->ncu_node.u_link.nwamd_link_dlpi_thread,
		    NULL);
		ncu->ncu_node.u_link.nwamd_link_dlpi_thread = 0;
		/* Unset properties before closing */
		nwamd_set_unset_link_properties(ncu, B_FALSE);
	}

	dlpi_close(ncu->ncu_node.u_link.nwamd_link_dhp);
	ncu->ncu_node.u_link.nwamd_link_dhp = NULL;
}
