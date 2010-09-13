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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include "metaGlobal.h"

/*
 * The list and the list lock are global for two external uses:
 * 1) C_CloseAllSessions need to close the head (repeatedly,
 *    until no more sessions exist).
 * 2) meta_object_find_by_handle needs to walk all sessions,
 *    searching each session object list for matching objects.
 */
pthread_rwlock_t meta_sessionlist_lock;
meta_session_t *meta_sessionlist_head;

/*
 * The following 2 variables are used for tracking the number of
 * sessions and number of rw sessios that are currently open
 *
 * They are being manipulated in the metaSession.c file, and being
 * referenced in the metaSlotToken.c file
 */
CK_ULONG num_meta_sessions;
CK_ULONG num_rw_meta_sessions;



static pthread_rwlock_t meta_sessionclose_lock;


/*
 * meta_sessionManager_initialize
 *
 * Called from meta_Initialize.  Initializes all the variables used
 * by the session manager.
 */
CK_RV
meta_sessionManager_initialize()
{

	if (pthread_rwlock_init(&meta_sessionlist_lock, NULL) != 0) {
		return (CKR_FUNCTION_FAILED);
	}

	if (pthread_rwlock_init(&meta_sessionclose_lock, NULL) != 0) {
		(void) pthread_rwlock_destroy(&meta_sessionlist_lock);
		return (CKR_FUNCTION_FAILED);
	}

	meta_sessionlist_head = NULL;
	num_meta_sessions = 0;
	num_rw_meta_sessions = 0;

	return (CKR_OK);
}

/*
 * meta_sessionManager_finalize
 *
 * Close all sessions, and destroy all the locks
 */
void
meta_sessionManager_finalize()
{
	/*
	 * Close any remaining metasessions, can just simply call
	 * meta_CloseAllSessions.  The METASLOT_SLOTID argument is
	 * not used, but need to be passed in.
	 */
	(void) meta_CloseAllSessions(METASLOT_SLOTID);

	(void) pthread_rwlock_destroy(&meta_sessionclose_lock);

	(void) pthread_rwlock_destroy(&meta_sessionlist_lock);
}

/*
 * meta_handle2session
 *
 * Convert a CK_SESSION_HANDLE to the corresponding metasession. If
 * successful, a write-lock on the session will be held to indicate
 * that it's in use. Call REFRELEASE() when finished.
 *
 */
CK_RV
meta_handle2session(CK_SESSION_HANDLE hSession, meta_session_t **session)
{
	meta_session_t *tmp_session = (meta_session_t *)(hSession);

	/* Check for bad args (eg CK_INVALID_HANDLE, which is 0/NULL). */
	if (tmp_session == NULL ||
	    tmp_session->magic_marker != METASLOT_SESSION_MAGIC) {
		return (CKR_SESSION_HANDLE_INVALID);
	}

	/*
	 * sessions can only be used by a single thread at a time.
	 * So, we need to get a write-lock.
	 */
	(void) pthread_rwlock_wrlock(&tmp_session->session_lock);

	/* Make sure this session is not in the process of being deleted */
	(void) pthread_mutex_lock(&tmp_session->isClosingSession_lock);
	if (tmp_session->isClosingSession) {
		(void) pthread_mutex_unlock(
		    &tmp_session->isClosingSession_lock);
		(void) pthread_rwlock_unlock(&tmp_session->session_lock);
		return (CKR_SESSION_HANDLE_INVALID);
	}
	(void) pthread_mutex_unlock(&tmp_session->isClosingSession_lock);

	*session = tmp_session;
	return (CKR_OK);
}


/*
 * meta_session_alloc
 */
CK_RV
meta_session_alloc(meta_session_t **session)
{
	meta_session_t *new_session;

	/* Allocate memory for the session. */
	new_session = calloc(1, sizeof (meta_session_t));
	if (new_session == NULL)
		return (CKR_HOST_MEMORY);

	(new_session->mech_support_info).supporting_slots
	    = malloc(meta_slotManager_get_slotcount() * sizeof (mechinfo_t *));
	if ((new_session->mech_support_info).supporting_slots == NULL) {
		free(new_session);
		return (CKR_HOST_MEMORY);
	}
	(new_session->mech_support_info).num_supporting_slots = 0;

	new_session->magic_marker = METASLOT_SESSION_MAGIC;
	(void) pthread_rwlock_init(&new_session->session_lock, NULL);
	(void) pthread_mutex_init(&new_session->isClosingSession_lock, NULL);
	(void) pthread_rwlock_init(&new_session->object_list_lock, NULL);

	*session = new_session;
	return (CKR_OK);
}


/*
 * meta_session_activate
 *
 * Create and add a session to the list of active meta sessions.
 */
CK_RV
meta_session_activate(meta_session_t *session)
{
	CK_RV rv = CKR_OK;

	/* Add session to the list of sessions. */
	(void) pthread_rwlock_wrlock(&meta_sessionlist_lock);
	INSERT_INTO_LIST(meta_sessionlist_head, session);
	(void) pthread_rwlock_unlock(&meta_sessionlist_lock);

	return (rv);
}

/*
 * meta_session_deactivate
 *
 *
 */
CK_RV
meta_session_deactivate(meta_session_t *session,
    boolean_t have_sessionlist_lock)
{
	boolean_t isLastSession = B_FALSE;
	meta_object_t *object;

	/* Safely resolve attempts of concurrent-close */
	(void) pthread_mutex_lock(&session->isClosingSession_lock);
	if (session->isClosingSession) {
		/* Lost a delete race. */
		(void) pthread_mutex_unlock(&session->isClosingSession_lock);
		REFRELEASE(session);
		return (CKR_SESSION_HANDLE_INVALID);
	}
	session->isClosingSession = B_TRUE;
	session->magic_marker = METASLOT_SESSION_BADMAGIC;
	(void) pthread_mutex_unlock(&session->isClosingSession_lock);

	/*
	 * Remove session from the session list. Once removed, it will not
	 * be possible for another thread to begin using the session.
	 */
	(void) pthread_rwlock_wrlock(&meta_sessionclose_lock);
	if (!have_sessionlist_lock) {
		(void) pthread_rwlock_wrlock(&meta_sessionlist_lock);
	}

	REMOVE_FROM_LIST(meta_sessionlist_head, session);
	if (meta_sessionlist_head == NULL) {
		isLastSession = B_TRUE;
	}
	if (!have_sessionlist_lock) {
		(void) pthread_rwlock_unlock(&meta_sessionlist_lock);
	}
	(void) pthread_rwlock_unlock(&meta_sessionclose_lock);

	(void) pthread_rwlock_unlock(&session->session_lock);

	/* Cleanup any in-progress operations. */
	if (session->op1.type != 0) {
		meta_operation_cleanup(session, session->op1.type, FALSE);
	}

	if (session->op1.session != NULL) {
		meta_release_slot_session(session->op1.session);
		session->op1.session = NULL;
	}

	/* Remove all the session metaobjects created in this session. */
	/* Basically, emulate C_DestroyObject, including safety h2s */
	while ((object = session->object_list_head) != NULL) {
		CK_RV rv;

		rv = meta_handle2object((CK_OBJECT_HANDLE)object, &object);
		if (rv != CKR_OK) {
			/* Can only happen if someone else just closed it. */
			continue;
		}

		rv = meta_object_deactivate(object, B_FALSE, B_TRUE);
		if (rv != CKR_OK) {
			continue;
		}

		rv = meta_object_dealloc(NULL, object, B_FALSE);
		if (rv != CKR_OK) {
			continue;
		}

	}

	if ((isLastSession) && (metaslot_logged_in())) {
		slot_session_t *slotsessp;
		CK_RV rv;

		rv = meta_get_slot_session(get_keystore_slotnum(), &slotsessp,
		    session->session_flags);
		if (rv != CKR_OK)
			return (rv);
		rv = FUNCLIST(slotsessp->fw_st_id)->C_Logout(
		    slotsessp->hSession);

		meta_release_slot_session(slotsessp);

		/* if C_Logout fails, just ignore the error */
		metaslot_set_logged_in_flag(B_FALSE);

		if (rv != CKR_OK)
			return (rv);

		/* need to deactivate all the PRIVATE token objects */
		rv = meta_token_object_deactivate(PRIVATE_TOKEN);
		if (rv != CKR_OK) {
			return (rv);
		}
	}

	return (CKR_OK);
}


/*
 * meta_session_dealloc
 *
 * Release the resources held by a metasession. If the session has been
 * activated, it must be deactivated first.
 */
void
meta_session_dealloc(meta_session_t *session)
{
	if ((session->find_objs_info).matched_objs) {
		free((session->find_objs_info).matched_objs);
	}

	free((session->mech_support_info).supporting_slots);

	/*
	 * If there were active operations, cleanup the slot session so that
	 * it can be reused (otherwise provider might complain that an
	 * operation is active).
	 */
	if (session->op1.type != 0)
		meta_operation_cleanup(session, session->op1.type, FALSE);

	/* Final object cleanup. */
	(void) pthread_rwlock_destroy(&session->session_lock);
	(void) pthread_mutex_destroy(&session->isClosingSession_lock);
	(void) pthread_rwlock_destroy(&session->object_list_lock);

	meta_session_delay_free(session);
}

/*
 * This function adds the to-be-freed meta session to a linked list.
 * When the number of sessions queued in the linked list reaches the
 * maximum threshold MAX_SESSION_TO_BE_FREED, it will free the first
 * session (FIFO) in the list.
 */
void
meta_session_delay_free(meta_session_t *sp)
{
	meta_session_t *tmp;

	(void) pthread_mutex_lock(&ses_delay_freed.ses_to_be_free_mutex);

	/* Add the newly deleted session at the end of the list */
	sp->next = NULL;
	if (ses_delay_freed.first == NULL) {
		ses_delay_freed.last = sp;
		ses_delay_freed.first = sp;
	} else {
		ses_delay_freed.last->next = sp;
		ses_delay_freed.last = sp;
	}

	if (++ses_delay_freed.count >= MAX_SESSION_TO_BE_FREED) {
		/*
		 * Free the first session in the list only if
		 * the total count reaches maximum threshold.
		 */
		ses_delay_freed.count--;
		tmp = ses_delay_freed.first->next;
		free(ses_delay_freed.first);
		ses_delay_freed.first = tmp;
	}
	(void) pthread_mutex_unlock(&ses_delay_freed.ses_to_be_free_mutex);
}
