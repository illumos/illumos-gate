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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>
#include <stdlib.h>
#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Slot.h"
#include "pkcs11Session.h"


/*
 * pkcs11_session_add:
 * Create a session and add it to the list of sessions associated
 * with the slot it is being opened on.  The session handle, fwsessionp,
 * will be the memory address of the session, typecast to a CK_SESSION_HANDLE.
 *
 * Assumptions: slotp is a valid slot, mutexes are not held, and
 * the provider already successfully opened related session.
 */
CK_RV
pkcs11_session_add(pkcs11_slot_t *slotp, CK_SLOT_ID slot_id,
    CK_SESSION_HANDLE_PTR fwsessionp, CK_SESSION_HANDLE prov_sess)
{

	pkcs11_session_t *newhandle = malloc(sizeof (pkcs11_session_t));

	if (newhandle == NULL) {
		return (CKR_HOST_MEMORY);
	}

	newhandle->se_magic = PKCS11_SESSION_MAGIC;
	newhandle->se_handle = prov_sess;
	newhandle->se_slotid = slot_id;

	(void) pthread_mutex_lock(&slotp->sl_mutex);

	/* Insert the new session in the front of the slot's session list */
	if (slotp->sl_sess_list == NULL) {
		slotp->sl_sess_list = newhandle;
		newhandle->se_prev = NULL;
		newhandle->se_next = NULL;
	} else {
		slotp->sl_sess_list->se_prev = newhandle;
		newhandle->se_next = slotp->sl_sess_list;
		newhandle->se_prev = NULL;
		slotp->sl_sess_list = newhandle;
	}

	/* Typecast the address of session structure to a session handle */
	*fwsessionp = (CK_SESSION_HANDLE)newhandle;

	(void) pthread_mutex_unlock(&slotp->sl_mutex);

	return (CKR_OK);
}

/*
 * pkcs11_session_delete:
 * Delete a session from a particular slot's session list.
 *
 * Assumptions: slotp is a valid slot, sessp is a valid session,
 * provider has already successfully closed this session, and
 * mutexes are not held.
 */
void
pkcs11_session_delete(pkcs11_slot_t *slotp, pkcs11_session_t *sessp)
{

	/* Acquire the slot's lock */
	(void) pthread_mutex_lock(&slotp->sl_mutex);

	if (slotp->sl_sess_list == sessp) {
		/* This is the first session in the list */
		if (sessp->se_next != NULL) {
			slotp->sl_sess_list = sessp->se_next;
			sessp->se_next->se_prev = NULL;
		} else {
			/* Session is the only one in the list */
			slotp->sl_sess_list = NULL;
		}
	} else {
		/* Session is not the first one in the list */
		if (sessp->se_next != NULL) {
			/* Session is in the middle of the list */
			sessp->se_prev->se_next = sessp->se_next;
			sessp->se_next->se_prev = sessp->se_prev;
		} else {
			/* Session is the last one in the list */
			sessp->se_prev->se_next = NULL;
		}
	}

	/* Mark session as no longer valid */
	sessp->se_magic = 0;

	free(sessp);

	(void) pthread_mutex_unlock(&slotp->sl_mutex);

}

/*
 * pkcs11_sessionlist_delete:
 * Delete all sessions associated with a particular slot's session list.
 *
 * Assumptions: slotp is a valid slot, no mutexes are held, and the
 * sessions were successfully closed with the provider already.
 */
void
pkcs11_sessionlist_delete(pkcs11_slot_t *slotp)
{

	pkcs11_session_t *sessp, *sess_nextp;

	sessp = slotp->sl_sess_list;

	/* Delete all the sessions in this slot's session list */
	while (sessp) {
		sess_nextp = sessp->se_next;

		pkcs11_session_delete(slotp, sessp);

		sessp = sess_nextp;
	}

	slotp->sl_sess_list = NULL;

}
