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
 * Functions for dealing with provider sessions
 */

#include <string.h>
#include <cryptoutil.h>
#include "metaGlobal.h"
#include "pkcs11Session.h"
#include "pkcs11Global.h"


/*
 * This is just a **WILD** guess for the maximum idle sessions to
 * keep for each slot.  This number should probably be adjusted
 * when there's more data from actual application use
 */
#define	MAX_IDLE_SESSIONS	100

/*
 * The following 5 variables are initialized at the time metaslot
 * is initialized.  They are not modified after they are initialized
 *
 * During initialization time, they are protected by the "initmutex"
 * defined in metaGeneral.c
 */
slot_data_t *slots;
CK_SLOT_ID metaslot_keystore_slotid;
static CK_ULONG num_slots;
static CK_ULONG objtok_slotnum;
static CK_ULONG softtoken_slotnum;
static boolean_t write_protected;

/* protects the "metaslotLoggedIn" variable */
static pthread_mutex_t metaslotLoggedIn_mutex = PTHREAD_MUTEX_INITIALIZER;
static boolean_t metaslotLoggedIn;

/*
 * meta_slotManager_initialize
 *
 * Called from C_Initialize. Allocates and initializes the storage needed
 * by the slot manager.
 */
CK_RV
meta_slotManager_initialize() {
	CK_ULONG slot_count = 0;
	CK_RV rv;
	CK_SLOT_ID i;

	/* Initialize the static variables */
	write_protected = B_FALSE;
	metaslotLoggedIn = B_FALSE;

	/*
	 * Count the number of slots in the framework.
	 * We start at ((slottable->st_first) + 1) instead of
	 * slottable->st_first because when we are here, metaslot is
	 * enabled, and st_first is always metaslot, which doesn't
	 * need to be counted.
	 */
	for (i = (slottable->st_first) + 1; i <= slottable->st_last; i++) {
		slot_count++;
	}

	/*
	 * This shouldn't happen, because there should at least
	 * be 1 other slot besides metaslot.
	 */
	if (slot_count < 1) {
		rv = CKR_FUNCTION_FAILED;
		goto clean_exit;
	}

	slots = calloc(slot_count, sizeof (slot_data_t));
	if (slots == NULL) {
		rv = CKR_HOST_MEMORY;
		goto clean_exit;
	}

	/*
	 * Store the slot IDs. Adjust for the fact that the first slot is
	 * actually us (metaslot).
	 */
	for (i = 0; i < slot_count; i++) {
		slots[i].fw_st_id = i + 1;
		(void) pthread_rwlock_init(
		    &(slots[i].tokenobject_list_lock), NULL);
	}
	num_slots = slot_count;

	return (CKR_OK);

clean_exit:
	if (slots) {
		free(slots);
		slots = NULL;
	}

	num_slots = 0;

	return (rv);
}


/*
 * meta_slotManager_finalize
 *
 * Called from C_Finalize. Deallocates any storage held by the slot manager.
 */
void
meta_slotManager_finalize() {
	CK_ULONG slot;

	/* If no slots to free, return */
	if (slots == NULL)
		return;
	/*
	 * No need to lock pool, we assume all meta sessions are closed.
	 *
	 * Close all sessions in the idle and persist list.
	 * The active list is empty.  It doesn't need to be checked.
	 */

	for (slot = 0; slot < num_slots; slot++) {
		slot_session_t *session, *next_session;

		/*
		 * The slotobjects associated with the session should have
		 * been closed when the metaobjects were closed. Thus, no
		 * need to do anything here.
		 */

		session = slots[slot].session_pool.idle_list_head;
		while (session) {
			next_session = session->next;
			(void) FUNCLIST(session->fw_st_id)->C_CloseSession(
			    session->hSession);
			(void) pthread_rwlock_destroy(
				&session->object_list_lock);
			free(session);
			session = next_session;
		}

		session = slots[slot].session_pool.persist_list_head;
		while (session) {
			next_session = session->next;
			(void) FUNCLIST(session->fw_st_id)->C_CloseSession(
			    session->hSession);
			(void) pthread_rwlock_destroy(
				&session->object_list_lock);
			free(session);
			session = next_session;
		}

		(void) pthread_rwlock_destroy(
			&slots[slot].tokenobject_list_lock);
	}

	free(slots);
	slots = NULL;
	num_slots = 0;
}


/*
 * meta_slotManager_find_object_token()
 *
 * Called from meta_Initialize. Searches for the "object token," which is used
 * for storing token objects and loging into.
 *
 * We do the search using the following algorithm.
 *
 * If either ${METASLOT_OBJECTSTORE_SLOT} or ${METASLOT_OBJECTSTORE_TOKEN}
 * environment variable is defined, the value of the defined variable(s)
 * will be used for the match.  All token and slot values defined system-wide
 * will be ignored.
 *
 * If neither variables above are defined, the system-wide values defined
 * in pkcs11.conf are used.
 *
 * If neither environment variables or system-wide values are defined,
 * or if none of the existing slots/tokens match the defined
 * values, the first slot after metaslot will be used as the default.
 *
 */
void
meta_slotManager_find_object_token() {
	CK_ULONG slot;
	boolean_t found = B_FALSE;
	CK_RV rv;
	unsigned int num_match_needed = 0;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;

	if (metaslot_config.keystore_token_specified) {
		num_match_needed++;
	}

	if (metaslot_config.keystore_slot_specified) {
		num_match_needed++;
	}

	if (num_match_needed == 0) {
		goto skip_search;
	}

	for (slot = 0; slot < num_slots; slot++) {
		unsigned int num_matched = 0;
		boolean_t have_tokeninfo = B_FALSE;
		CK_SLOT_ID true_id, fw_st_id;

		fw_st_id = slots[slot].fw_st_id;
		true_id = TRUEID(fw_st_id);

		(void) memset(&slotinfo, 0, sizeof (CK_SLOT_INFO));
		rv = FUNCLIST(fw_st_id)->C_GetSlotInfo(true_id,
		    &slotinfo);
		if (rv != CKR_OK)
			continue;

		if (strncmp((char *)SOFT_SLOT_DESCRIPTION,
		    (char *)slotinfo.slotDescription,
		    SLOT_DESCRIPTION_SIZE) == 0) {
			softtoken_slotnum = slot;
		}

		if (metaslot_config.keystore_slot_specified) {

			unsigned char *slot;
			size_t slot_str_len;

			rv = FUNCLIST(fw_st_id)->C_GetSlotInfo(true_id,
			    &slotinfo);
			if (rv != CKR_OK)
				continue;

			/*
			 * pad slot description from user/system configuration
			 * with spaces
			 */
			slot = metaslot_config.keystore_slot;
			slot_str_len = strlen((char *)slot);
			(void) memset(slot + slot_str_len, ' ',
			    SLOT_DESCRIPTION_SIZE - slot_str_len);

			/*
			 * The PKCS#11 strings are not null-terminated, so,
			 * we just compare SLOT_DESCRIPTION_SIZE bytes
			 */
			if (strncmp((char *)slot,
			    (char *)slotinfo.slotDescription,
			    SLOT_DESCRIPTION_SIZE) == 0) {
				num_matched++;
			}
		}

		if (metaslot_config.keystore_token_specified) {
			unsigned char *token;
			size_t token_str_len;

			rv = FUNCLIST(fw_st_id)->C_GetTokenInfo(true_id,
			    &tokeninfo);

			if (rv != CKR_OK) {
				continue;
			}

			have_tokeninfo = B_TRUE;

			/*
			 * pad slot description from user/system configuration
			 * with spaces
			 */
			token = metaslot_config.keystore_token;
			token_str_len = strlen((char *)token);
			(void) memset(token + token_str_len, ' ',
			    TOKEN_LABEL_SIZE - token_str_len);

			/*
			 * The PKCS#11 strings are not null-terminated.
			 * So, just compare TOKEN_LABEL_SIZE bytes
			 */
			if (strncmp((char *)token, (char *)tokeninfo.label,
			    TOKEN_LABEL_SIZE) == 0) {
				num_matched++;
			}
		}

		if (num_match_needed == num_matched) {
			/* match is found */

			if (!have_tokeninfo) {
				rv = FUNCLIST(fw_st_id)->C_GetTokenInfo(true_id,
				    &tokeninfo);
				if (rv != CKR_OK) {
					continue;
				}
			}


			if (tokeninfo.flags & CKF_WRITE_PROTECTED) {
				/*
				 * Currently this is the only time that
				 * the write_protected state is set, and
				 * it is never cleared. The token could
				 * clear (or set!) this flag later on.
				 * We might want to adjust the state
				 * of metaslot, but there's know way to know
				 * when a token changes this flag.
				 */
				write_protected = B_TRUE;
			}

			found = B_TRUE;
			break;
		}
	}

skip_search:
	if (found) {
		objtok_slotnum = slot;
	} else {
		/*
		 * if slot and/or token is not defined for the keystore,
		 * just use the first available slot as keystore
		 */
		objtok_slotnum = 0;
	}
	slots[objtok_slotnum].session_pool.keep_one_alive = B_TRUE;
	metaslot_keystore_slotid = slots[objtok_slotnum].fw_st_id;
}


CK_ULONG
get_keystore_slotnum()
{
	return (objtok_slotnum);
}

CK_ULONG
get_softtoken_slotnum()
{
	return (softtoken_slotnum);
}

CK_SLOT_ID
meta_slotManager_get_framework_table_id(CK_ULONG slotnum)
{
	/*
	 * This is only used internally, and so the slotnum should always
	 * be valid.
	 */
	return (slots[slotnum].fw_st_id);
}

CK_ULONG
meta_slotManager_get_slotcount()
{
	return (num_slots);
}

boolean_t
meta_slotManager_token_write_protected()
{
	return (write_protected);
}

/*
 * Find a session in the given list that matches the specified flags.
 * If such a session is found, it will be removed from the list, and
 * returned to the caller.  If such a session is not found, will
 * return NULL
 */
static slot_session_t *
get_session(slot_session_t **session_list, CK_FLAGS flags)
{

	slot_session_t *tmp_session;

	tmp_session = *session_list;

	while (tmp_session != NULL) {
		if (tmp_session->session_flags == flags) {
			break;
		} else {
			tmp_session = tmp_session->next;
		}

	}

	if (tmp_session == NULL) {
		/* no match */
		return (NULL);
	}

	/* Remove from list */
	REMOVE_FROM_LIST(*session_list, tmp_session);
	return (tmp_session);
}

/*
 * meta_get_slot_session
 *
 * Call to get a session with a specific slot/token.
 *
 * NOTE - We assume the slot allows an unlimited number of sessions. We
 * could look at what's reported in the token info, but that information is
 * not always set. It's also unclear when we should (A) wait for one to become
 * available, (B) skip the slot for now or (C) return a fatal error. The
 * extra complexity is not worth it.
 *
 */
CK_RV
meta_get_slot_session(CK_ULONG slotnum, slot_session_t **session,
    CK_FLAGS flags) {
	session_pool_t *pool;
	slot_session_t *new_session, *tmp_session;
	CK_RV rv;
	CK_SLOT_ID fw_st_id, true_id;

	if (slotnum >= num_slots) {
		return (CKR_SLOT_ID_INVALID);
	}

	pool = &slots[slotnum].session_pool;

	/*
	 * Try to reuse an existing session.
	 */

	(void) pthread_mutex_lock(&pool->list_lock);

	if (pool->idle_list_head != NULL) {
		tmp_session = get_session(&(pool->idle_list_head), flags);
		if (tmp_session != NULL) {
			/* Add to active list */
			INSERT_INTO_LIST(pool->active_list_head, tmp_session);
			*session = tmp_session;
			pool->num_idle_sessions--;
			(void) pthread_mutex_unlock(&pool->list_lock);
			return (CKR_OK);
		}
	}

	if (pool->persist_list_head != NULL) {
		tmp_session = get_session(&(pool->persist_list_head), flags);
		if (tmp_session != NULL) {
			/* Add to active list */
			INSERT_INTO_LIST(pool->active_list_head, tmp_session);
			*session = tmp_session;
			(void) pthread_mutex_unlock(&pool->list_lock);
			return (CKR_OK);
		}
	}
	(void) pthread_mutex_unlock(&pool->list_lock);

	fw_st_id = slots[slotnum].fw_st_id;
	true_id = TRUEID(fw_st_id);

	new_session = calloc(1, sizeof (slot_session_t));
	if (new_session == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/* initialize slotsession */
	new_session->slotnum = slotnum;
	new_session->fw_st_id = fw_st_id;
	new_session->object_list_head = NULL;
	new_session->session_flags = flags;
	(void) pthread_rwlock_init(&new_session->object_list_lock, NULL);

	rv = FUNCLIST(fw_st_id)->C_OpenSession(true_id, flags, NULL, NULL,
	    &new_session->hSession);

	if (rv == CKR_TOKEN_WRITE_PROTECTED) {
		/* Retry with a RO session. */
		new_session->session_flags &= ~CKF_SERIAL_SESSION;
		rv = FUNCLIST(fw_st_id)->C_OpenSession(true_id,
		    new_session->session_flags, NULL, NULL,
		    &new_session->hSession);
	}

	if (rv != CKR_OK) {
		free(new_session);
		return (CKR_FUNCTION_FAILED);
	}

	/* Insert session into active list */
	(void) pthread_mutex_lock(&pool->list_lock);
	INSERT_INTO_LIST(pool->active_list_head, new_session);
	(void) pthread_mutex_unlock(&pool->list_lock);
	*session = new_session;
	return (CKR_OK);
}


/*
 * meta_release_slot_session
 *
 * Call to release a session obtained via meta_get_slot_session()
 */
void
meta_release_slot_session(slot_session_t *session) {
	session_pool_t *pool;
	boolean_t must_retain, can_close = B_FALSE;
	boolean_t this_is_last_session = B_FALSE;

	pool = &slots[session->slotnum].session_pool;

	/* Note that the active_list must have >= 1 entry (this session) */
	if (pool->persist_list_head == NULL &&
	    pool->idle_list_head == NULL &&
	    pool->active_list_head->next == NULL)
		this_is_last_session = B_TRUE;

	/*
	 * If the session has session objects, we need to retain it. Also
	 * retain it if it's the only session holding login state (or handles
	 * to public token objects)
	 */
	must_retain = session->object_list_head != NULL ||
	    (pool->keep_one_alive && this_is_last_session);

	if ((!must_retain) && (pool->num_idle_sessions > MAX_IDLE_SESSIONS)) {
		can_close = B_TRUE;
	}

	(void) pthread_mutex_lock(&pool->list_lock);
	/* remove from active list */
	REMOVE_FROM_LIST(pool->active_list_head, session);

	if (must_retain) {
		/* insert into persist list */
		INSERT_INTO_LIST(pool->persist_list_head, session);
		(void) pthread_mutex_unlock(&pool->list_lock);
		return;
	} else if (!can_close) {
		/* insert into idle list */
		INSERT_INTO_LIST(pool->idle_list_head, session);
		pool->num_idle_sessions++;
		(void) pthread_mutex_unlock(&pool->list_lock);
		return;
	}

	(void) pthread_mutex_unlock(&pool->list_lock);

	(void) FUNCLIST(session->fw_st_id)->C_CloseSession(session->hSession);

	(void) pthread_rwlock_destroy(&session->object_list_lock);
	free(session);
}

/*
 * Returns whether metaslot has directly logged in
 */
boolean_t
metaslot_logged_in()
{
	return (metaslotLoggedIn);
}

void
metaslot_set_logged_in_flag(boolean_t value)
{
	(void) pthread_mutex_lock(&metaslotLoggedIn_mutex);
	metaslotLoggedIn = value;
	(void) pthread_mutex_unlock(&metaslotLoggedIn_mutex);
}
