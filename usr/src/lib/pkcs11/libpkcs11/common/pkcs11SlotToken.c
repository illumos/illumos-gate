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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Conf.h"
#include "pkcs11Slot.h"
#include "metaGlobal.h"

static void *listener_waitforslotevent(void *arg);
static void *child_waitforslotevent(void *arg);

/*
 * C_GetSlotList is implemented entirely within this framework,
 * using the slottable that was created during the call to
 * C_Initialize in pkcs11_slot_mapping().  The plugged in providers
 * are only queried when tokenPresent is set.
 *
 * If metaslot is enabled, the slot that provides keystore support
 * needs to be hidden.  Therefore, even when fastpath is enabled,
 * we can't go through fastpath because the slot needs to be
 * hidden.
 */
CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount)
{

	CK_RV rv;
	CK_RV prov_rv;
	CK_SLOT_ID true_id;
	CK_SLOT_INFO_PTR pinfo;
	CK_SLOT_ID count = 0, i;
	CK_SLOT_ID slot_id; /* slot ID for returning to the application */

	/* Check for a fastpath */
	if ((purefastpath || policyfastpath) && (!metaslot_enabled)) {
		return (fast_funcs->C_GetSlotList(tokenPresent, pSlotList,
			    pulCount));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pulCount == NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	if (tokenPresent) {
		/* Need to allocate memory for pinfo */
		pinfo = malloc(sizeof (CK_SLOT_INFO));
		if (pinfo == NULL) {
			return (CKR_HOST_MEMORY);
		}
	}

	/*
	 * Count the number of valid slots for returning to the application.
	 * If metaslot is enabled, the slot providing keystore support for
	 * metaslot is skipped.  Therefore, we can't simply sequentially
	 * assign "i" as the slot id to be returned to the application.
	 * The variable "slot_id" is used for keeping track of the
	 * next slot id to be assigned.
	 */
	slot_id = slottable->st_first;
	for (i = slottable->st_first; i <= slottable->st_last; i++) {
		if ((pkcs11_is_valid_slot(i) == CKR_OK) &&
		    ((!metaslot_enabled) || (i != metaslot_keystore_slotid))) {

			/* Check if token present is required */
			if (tokenPresent) {
				/* Check with provider */
				true_id = TRUEID(i);
				prov_rv = FUNCLIST(i)->
				    C_GetSlotInfo(true_id, pinfo);
				if ((prov_rv != CKR_OK) ||
				    !(pinfo->flags & CKF_TOKEN_PRESENT)) {
					continue;
				}
			}
			/* Fill in the given buffer if it is sufficient */
			if (pSlotList && (*pulCount > count)) {
				pSlotList[count] = slot_id;
				slot_id++;
			}
			count++;
		}
	}

	/* pSlotList set to NULL means caller only wants count */
	if ((*pulCount < count) && (pSlotList != NULL)) {
		rv = CKR_BUFFER_TOO_SMALL;
	} else {
		rv = CKR_OK;
	}

	*pulCount = count;

	if (tokenPresent) {
		free(pinfo);
	}

	return (rv);
}

CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{

	CK_RV rv;
	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (slotID == METASLOT_FRAMEWORK_ID) {
		/* just need to get metaslot information */
		return (meta_GetSlotInfo(METASLOT_SLOTID, pInfo));
	}

	/* Check that slotID is valid */
	if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id) != CKR_OK) {
		return (CKR_SLOT_ID_INVALID);
	}

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_GetSlotInfo(fw_st_id, pInfo));
	}

	true_id = TRUEID(fw_st_id);

	rv = FUNCLIST(fw_st_id)->C_GetSlotInfo(true_id, pInfo);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (slotID == METASLOT_FRAMEWORK_ID) {
		/* just need to get metaslot information */
		return (meta_GetTokenInfo(METASLOT_SLOTID, pInfo));
	}

	/* Check that slotID is valid */
	if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id) != CKR_OK) {
		return (CKR_SLOT_ID_INVALID);
	}

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_GetTokenInfo(fw_st_id, pInfo));
	}

	true_id = TRUEID(fw_st_id);

	rv = FUNCLIST(fw_st_id)->C_GetTokenInfo(true_id, pInfo);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

/*
 * C_WaitForSlotEvent cannot be a direct pass through to the underlying
 * provider (except in the case of fastpath), due to the complex nature
 * of this function.  The calling application is asking to be alerted
 * when an event has occurred on any of the slots in the framework, so
 * we need to check with all underlying providers and ask for events
 * on any of their slots.  If this is called in blocking mode, we will
 * need to start threads to wait for slot events for each provider
 * plugged into the framework.
 */
CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	CK_SLOT_ID i, j;
	uint32_t prov_id;
	int32_t last_prov_id = -1;
	CK_RV rv = CKR_OK;
	CK_SLOT_ID event_slot;
	pkcs11_slot_t *cur_slot;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_WaitForSlotEvent(flags, pSlot,
			    pReserved));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (pReserved != NULL) {
		return (CKR_ARGUMENTS_BAD);
	}

	/*
	 * Check to see if we're already blocking on another threads
	 * call to this function.  If so, behaviour is undefined so
	 * we should return to application.
	 */
	(void) pthread_mutex_lock(&slottable->st_mutex);
	if ((slottable->st_blocking) || (slottable->st_wfse_active)) {
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_FUNCTION_FAILED);
	} else {
		slottable->st_wfse_active = B_TRUE;
		(void) pthread_mutex_unlock(&slottable->st_mutex);
	}

	/*
	 * Check first to see if any events have been recorded
	 * already on any of the slots, regardless of blocking or
	 * thread status.
	 */
	for (i = slottable->st_first; i <= slottable->st_last; i++) {

		cur_slot = slottable->st_slots[i];

		if (cur_slot->sl_wfse_state == WFSE_EVENT) {

			/* found one, clear event and notify application */

			(void) pthread_mutex_lock(&cur_slot->sl_mutex);
			cur_slot->sl_wfse_state = WFSE_CLEAR;
			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);
			*pSlot = i;

			/*
			 * This event has been captured, clear the function's
			 * active status.  Other threads may now enter this
			 * function.
			 */
			(void) pthread_mutex_lock(&slottable->st_mutex);
			slottable->st_wfse_active = B_FALSE;
			(void) pthread_mutex_unlock(&slottable->st_mutex);
			return (CKR_OK);
		}
	}

	/*
	 * We could not find any existing event, so let's see
	 * if we can block and start threads to watch for events.
	 */
	if (flags & CKF_DONT_BLOCK) {
		/*
		 * Application does not want us to block so check with
		 * underlying providers to see if any events have occurred.
		 * Not every provider will have implemented this function,
		 * so error codes or CKR_NO_EVENT can be ignored.
		 */

		for (i = slottable->st_first; i <= slottable->st_last; i++) {
			prov_id = slottable->st_slots[i]->sl_prov_id;
			cur_slot = slottable->st_slots[i];

			/*
			 * Only do process once per provider.
			 */
			if (prov_id == last_prov_id) {
				continue;
			}

			/*
			 * Check to make sure a child thread is not already
			 * running, due to another of the application's
			 * thread calling this function.
			 */
			(void) pthread_mutex_lock(&cur_slot->sl_mutex);
			if (cur_slot->sl_wfse_state == WFSE_ACTIVE) {
				(void) pthread_mutex_unlock(
					&cur_slot->sl_mutex);
				continue;
			}

			cur_slot->sl_wfse_state = WFSE_ACTIVE;


			/*
			 * Release the hold on the slot's mutex while we
			 * are waiting for this function to complete.
			 */
			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);

			rv = FUNCLIST(i)->C_WaitForSlotEvent(flags,
			    pSlot, pReserved);

			(void) pthread_mutex_lock(&cur_slot->sl_mutex);

			cur_slot->sl_wfse_state = WFSE_CLEAR;

			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);

			/* See if we've found a slot with an event */
			if ((rv == CKR_OK) && (pSlot != NULL)) {
				/*
				 * Try to map the returned slotid to a slot
				 * allocated by the framework.  All slots from
				 * one provider are adjacent in the framework's
				 * slottable, so search for a mapping while
				 * the prov_id field is the same.
				 */
				j = i;
				while (prov_id ==
				    slottable->st_slots[j]->sl_prov_id) {

					/* Find the slot, remap pSlot */
					if (*pSlot == TRUEID(j)) {
						*pSlot = j;
						(void) pthread_mutex_lock(
							&slottable->st_mutex);
						slottable->st_wfse_active =
						    B_FALSE;
						(void) pthread_mutex_unlock(
							&slottable->st_mutex);
						return (CKR_OK);
					}
					j++;
				}

			}

			/*
			 * If we reach this part of the loop, this
			 * provider either had no events, did not support
			 * this function, or set pSlot to a value we
			 * could not find in the slots associated with
			 * this provider. Continue checking with remaining
			 * providers.
			 */
			last_prov_id = prov_id;
		}

		/* No provider had any events */
		(void) pthread_mutex_lock(&slottable->st_mutex);
		slottable->st_wfse_active = B_FALSE;
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_NO_EVENT);

	} else if (!(flags & CKF_DONT_BLOCK) && (pkcs11_cant_create_threads)) {
		/*
		 * Application has asked us to block, but forbidden
		 * us from creating threads.  This is too risky to perform
		 * with underlying providers (we may block indefinitely),
		 * so will return an error in this case.
		 */
		(void) pthread_mutex_lock(&slottable->st_mutex);
		slottable->st_wfse_active = B_FALSE;
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_FUNCTION_FAILED);
	}

	/*
	 * Grab the st_start_mutex now, which will prevent the listener
	 * thread from signaling on st_start_cond before we're ready to
	 * wait for it.
	 */
	(void) pthread_mutex_lock(&slottable->st_start_mutex);

	/*
	 * Application allows us to create threads and has
	 * asked us to block.  Create listener thread to wait for
	 * child threads to return.
	 */
	(void) pthread_mutex_lock(&slottable->st_mutex);
	if (pthread_create(&slottable->st_tid, NULL,
		listener_waitforslotevent, NULL) != 0) {
		slottable->st_wfse_active = B_FALSE;
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		(void) pthread_mutex_unlock(&slottable->st_start_mutex);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_unlock(&slottable->st_mutex);

	/*
	 * Wait for the listening thread to get started before
	 * we spawn child threads.
	 */
	(void) pthread_cond_wait(&slottable->st_start_cond,
	    &slottable->st_start_mutex);
	(void) pthread_mutex_unlock(&slottable->st_start_mutex);

	/*
	 * Need to hold the mutex on the entire slottable for the
	 * entire setup of the child threads.  Otherwise, the first
	 * child thread may complete before a later child thread is
	 * fully started, resulting in an inaccurate value of
	 * st_thr_count and a potential race condition.
	 */
	(void) pthread_mutex_lock(&slottable->st_mutex);

	/*
	 * Create child threads to check with the plugged in providers
	 * to check for events.  Keep a count of the current open threads,
	 * so the listener thread knows when there are no more children
	 * to listen for.  Also, make sure a thread is not already active
	 * for that provider.
	 */
	for (i = slottable->st_first; i <= slottable->st_last; i++) {
		prov_id = slottable->st_slots[i]->sl_prov_id;
		cur_slot = slottable->st_slots[i];

		/*
		 * Only do process once per provider.
		 */
		if (prov_id == last_prov_id) {
			continue;
		}

		/*
		 * Check to make sure a child thread is not already running,
		 * due to another of the application's threads calling
		 * this function. Also, check that the provider has actually
		 * implemented this function.
		 */
		(void) pthread_mutex_lock(&cur_slot->sl_mutex);
		if ((cur_slot->sl_wfse_state == WFSE_ACTIVE) ||
		    (cur_slot->sl_no_wfse)) {
			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);
			last_prov_id = prov_id;
			continue;
		}

		/* Set slot to active */
		cur_slot->sl_wfse_state = WFSE_ACTIVE;

		/*
		 * set up variable to pass arguments to child threads.
		 * Only need to set up once, as values will remain the
		 * same for each successive call.
		 */
		if (cur_slot->sl_wfse_args == NULL) {
			cur_slot->sl_wfse_args = malloc(sizeof (wfse_args_t));

			if (cur_slot->sl_wfse_args == NULL) {
				(void) pthread_mutex_unlock(
					&cur_slot->sl_mutex);
				slottable->st_wfse_active = B_FALSE;
				(void) pthread_mutex_unlock(
					&slottable->st_mutex);
				return (CKR_HOST_MEMORY);
			}
			cur_slot->sl_wfse_args->flags = flags;
			cur_slot->sl_wfse_args->pReserved = pReserved;
			cur_slot->sl_wfse_args->slotid = i;
		}

		/* Create child thread */
		if (pthread_create(&cur_slot->sl_tid, NULL,
			child_waitforslotevent,
			(void *)cur_slot->sl_wfse_args) != 0) {
			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);
			continue;
		}

		(void) pthread_mutex_unlock(&cur_slot->sl_mutex);

		/*
		 * This counter is decremented every time a
		 * child_waitforslotevent() wakes up the listener.
		 */
		slottable->st_thr_count++;

		last_prov_id = prov_id;
	}

	/* If no children are listening, kill the listener */
	if (slottable->st_thr_count == 0) {
		(void) pthread_cancel(slottable->st_tid);

		/* If there are no child threads, no event will occur */
		slottable->st_wfse_active = B_FALSE;
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_NO_EVENT);
	}

	(void) pthread_mutex_unlock(&slottable->st_mutex);

	/* Wait for listener thread to terminate */
	(void) pthread_join(slottable->st_tid, NULL);

	/* Make sure C_Finalize has not been called */
	if (!pkcs11_initialized) {
		(void) pthread_mutex_lock(&slottable->st_mutex);
		slottable->st_wfse_active = B_FALSE;
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* See if any events actually occurred */
	(void) pthread_mutex_lock(&slottable->st_mutex);
	event_slot = slottable->st_event_slot;
	(void) pthread_mutex_unlock(&slottable->st_mutex);

	if (pkcs11_is_valid_slot(event_slot) == CKR_OK) {

		(void) pthread_mutex_lock(&slottable->
		    st_slots[event_slot]->sl_mutex);
		if (slottable->st_slots[event_slot]->
		    sl_wfse_state == WFSE_EVENT) {

			/* An event has occurred on this slot */
			slottable->st_slots[event_slot]->sl_wfse_state =
			    WFSE_CLEAR;
			(void) pthread_mutex_unlock(&slottable->
			    st_slots[event_slot]->sl_mutex);
			*pSlot = event_slot;
			(void) pthread_mutex_lock(&slottable->st_mutex);
			slottable->st_blocking = B_FALSE;
			slottable->st_wfse_active = B_FALSE;
			(void) pthread_mutex_unlock(&slottable->st_mutex);
			return (CKR_OK);
		} else {
			(void) pthread_mutex_unlock(&slottable->
			    st_slots[event_slot]->sl_mutex);
		}
	}

	(void) pthread_mutex_lock(&slottable->st_mutex);
	slottable->st_blocking = B_FALSE;
	slottable->st_wfse_active = B_FALSE;
	(void) pthread_mutex_unlock(&slottable->st_mutex);

	/* No provider reported any events, or no provider implemented this */
	return (CKR_NO_EVENT);
}

/*
 * C_GetMechanismList cannot just be a direct pass through to the
 * underlying provider, because we allow the administrator to
 * disable certain mechanisms from specific providers.  This affects
 * both pulCount and pMechanismList.  Only when the fastpath with
 * no policy is in effect can we pass through directly to the
 * underlying provider.
 *
 * It is necessary, for policy filtering, to get the actual list
 * of mechanisms from the underlying provider, even if the calling
 * application is just requesting a count.  It is the only way to
 * get an accurate count of the number of mechanisms actually available.
 */
CK_RV
C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;
	CK_ULONG mech_count;
	CK_ULONG tmpmech_count;
	CK_MECHANISM_TYPE_PTR pmech_list, tmpmech_list;
	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */
	CK_FUNCTION_LIST_PTR prov_funcs;

	CK_ULONG i;

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (slotID == METASLOT_FRAMEWORK_ID) {
		return (meta_GetMechanismList(METASLOT_SLOTID, pMechanismList,
		    pulCount));
	}

	/* Check that slotID is valid */
	if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id) != CKR_OK) {
		return (CKR_SLOT_ID_INVALID);
	}

	/* Check for pure fastpath */
	if (purefastpath) {
		return (fast_funcs->C_GetMechanismList(fw_st_id,
		    pMechanismList, pulCount));
	}

	if (policyfastpath) {
		true_id = fw_st_id;
		slotID = fast_slot;
		prov_funcs = fast_funcs;
	} else {
		true_id = TRUEID(fw_st_id);
		prov_funcs = FUNCLIST(fw_st_id);
	}

	mech_count = 0;
	tmpmech_count = MECHLIST_SIZE;

	/*
	 * Allocate memory for a mechanism list.  We are assuming
	 * that most mechanism lists will be less than MECHLIST_SIZE.
	 * If that is not enough memory, we will try a second time
	 * with more memory allocated.
	 */
	pmech_list = malloc(tmpmech_count * sizeof (CK_MECHANISM_TYPE));

	if (pmech_list == NULL) {
		return (CKR_HOST_MEMORY);
	}

	/*
	 * Attempt to get the mechanism list.  PKCS11 supports
	 * removable media, so the mechanism list of a slot can vary
	 * over the life of the application.
	 */
	rv = prov_funcs->C_GetMechanismList(true_id,
	    pmech_list, &tmpmech_count);

	if (rv == CKR_BUFFER_TOO_SMALL) {
		/* Need to use more space */
		tmpmech_list = pmech_list;
		pmech_list = realloc
		    (tmpmech_list, tmpmech_count * sizeof (CK_MECHANISM_TYPE));

		if (pmech_list == NULL) {
			free(tmpmech_list);
			return (CKR_HOST_MEMORY);
		}

		/* Try again to get mechanism list. */
		rv = prov_funcs->C_GetMechanismList(true_id,
		    pmech_list, &tmpmech_count);

	}

	/*
	 * Present consistent face to calling application.
	 * If something strange has happened, or this function
	 * is not supported by this provider, return a count
	 * of zero mechanisms.
	 */
	if (rv != CKR_OK) {
		*pulCount = 0;
		free(pmech_list);
		return (CKR_OK);
	}

	/*
	 * Process the mechanism list, removing any mechanisms
	 * that are disabled via the framework.  Even if the
	 * application is only asking for a count, we must
	 * process the actual mechanisms being offered by this slot.
	 * We could not just subtract our stored count of disabled
	 * mechanisms, since it is not guaranteed that those
	 * mechanisms are actually supported by the slot.
	 */
	for (i = 0; i < tmpmech_count; i++) {
		/* Filter out the disabled mechanisms */
		if (pkcs11_is_dismech(fw_st_id, pmech_list[i])) {
			continue;
		}

		/*
		 * Only set pMechanismList if enough memory
		 * is available.  If it was set to NULL
		 * originally, this loop will just be counting
		 * mechanims.
		 */
		if (pMechanismList && (*pulCount > mech_count)) {
			pMechanismList[mech_count] = pmech_list[i];
		}
		mech_count++;
	}

	/*
	 * Catch the case where pMechanismList was not set to NULL,
	 * yet the buffer was not large enough.  If pMechanismList is
	 * set to NULL, this function will simply set pulCount and
	 * return CKR_OK.
	 */
	if ((*pulCount < mech_count) && (pMechanismList != NULL)) {
		*pulCount = mech_count;
		free(pmech_list);
		return (CKR_BUFFER_TOO_SMALL);
	}

	*pulCount = mech_count;
	free(pmech_list);

	return (CKR_OK);
}


CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;
	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */
	CK_FUNCTION_LIST_PTR prov_funcs;

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (slotID == METASLOT_FRAMEWORK_ID) {
		/* just need to get metaslot information */
		return (meta_GetMechanismInfo(METASLOT_SLOTID, type, pInfo));
	}

	/* Check that slotID is valid */
	if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id) != CKR_OK) {
		return (CKR_SLOT_ID_INVALID);
	}

	/* Check for pure fastpath */
	if (purefastpath) {
		return (fast_funcs->C_GetMechanismInfo(fw_st_id, type, pInfo));
	}

	if (policyfastpath) {
		true_id = fw_st_id;
		slotID = fast_slot;
		prov_funcs = fast_funcs;
	} else {
		true_id = TRUEID(fw_st_id);
		prov_funcs = FUNCLIST(fw_st_id);
	}

	/* Make sure this is not a disabled mechanism */
	if (pkcs11_is_dismech(fw_st_id, type)) {
		return (CKR_MECHANISM_INVALID);
	}

	rv = prov_funcs->C_GetMechanismInfo(true_id, type, pInfo);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}


CK_RV
C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
    CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv;
	CK_SLOT_ID true_id;
	CK_SLOT_ID fw_st_id; /* id for accessing framework's slottable */

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	if (slotID == METASLOT_FRAMEWORK_ID) {
		/* just need to get metaslot information */
		return (meta_InitToken(METASLOT_SLOTID, pPin, ulPinLen,
		    pLabel));
	}

	/* Check that slotID is valid */
	if (pkcs11_validate_and_convert_slotid(slotID, &fw_st_id) != CKR_OK) {
		return (CKR_SLOT_ID_INVALID);
	}

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_InitToken(fw_st_id, pPin, ulPinLen,
			    pLabel));
	}

	true_id = TRUEID(fw_st_id);

	rv = FUNCLIST(fw_st_id)->C_InitToken(true_id, pPin, ulPinLen, pLabel);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

CK_RV
C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{

	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_InitPIN(hSession, pPin, ulPinLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Initialize the PIN with the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_InitPIN(sessp->se_handle,
	    pPin, ulPinLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
	CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin,
	CK_ULONG ulNewPinLen)
{
	CK_RV rv;
	pkcs11_session_t *sessp;

	/* Check for a fastpath */
	if (purefastpath || policyfastpath) {
		return (fast_funcs->C_SetPIN(hSession, pOldPin, ulOldPinLen,
			    pNewPin, ulNewPinLen));
	}

	if (!pkcs11_initialized) {
		return (CKR_CRYPTOKI_NOT_INITIALIZED);
	}

	/* Obtain the session pointer */
	HANDLE2SESSION(hSession, sessp, rv);

	if (rv != CKR_OK) {
		return (rv);
	}

	/* Set the PIN with the provider */
	rv = FUNCLIST(sessp->se_slotid)->C_SetPIN(sessp->se_handle,
	    pOldPin, ulOldPinLen, pNewPin, ulNewPinLen);

	/* Present consistent interface to the application */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);

}

/*
 * listener_waitforslotevent is spawned by the main C_WaitForSlotEvent()
 * to listen for events from any of the providers.  It also watches the
 * count of threads, which may go to zero with no recorded events, if
 * none of the underlying providers have actually implemented this
 * function.
 */
/*ARGSUSED*/
static void *
listener_waitforslotevent(void *arg) {

	CK_SLOT_ID eventID;

	/* Mark slottable in state blocking */
	(void) pthread_mutex_lock(&slottable->st_mutex);
	slottable->st_blocking = B_TRUE;

	/* alert calling thread that this thread has started */
	(void) pthread_mutex_lock(&slottable->st_start_mutex);
	(void) pthread_cond_signal(&slottable->st_start_cond);
	(void) pthread_mutex_unlock(&slottable->st_start_mutex);

	/* wait for an event, or number of threads to reach zero */
	for (;;) {

		/*
		 * Make sure we've really been signaled, and not waking
		 * for another reason.
		 */
		while (slottable->st_list_signaled != B_TRUE) {
			(void) pthread_cond_wait(&slottable->st_wait_cond,
			    &slottable->st_mutex);
		}

		slottable->st_list_signaled = B_FALSE;

		/* See why we were woken up */
		if (!pkcs11_initialized) {
			/* Another thread has called C_Finalize() */
			(void) pthread_mutex_unlock(&slottable->st_mutex);
			return (NULL);
		}

		/* A thread has finished, decrement counter */
		slottable->st_thr_count--;

		eventID = slottable->st_event_slot;

		if (pkcs11_is_valid_slot(eventID) == CKR_OK) {

			(void) pthread_mutex_lock(&slottable->
			    st_slots[eventID]->sl_mutex);

			if (slottable->st_slots[eventID]->
			    sl_wfse_state == WFSE_EVENT) {
				(void) pthread_mutex_unlock(&slottable->
				    st_slots[eventID]->sl_mutex);

				/*
				 * st_event_slot is set to a valid value, event
				 * flag is set for that slot.  The flag will
				 * be cleared by main C_WaitForSlotEvent().
				 */
				(void) pthread_mutex_unlock(
					&slottable->st_mutex);

				pthread_exit(0);
			} else {
				(void) pthread_mutex_unlock(&slottable->
				    st_slots[eventID]->sl_mutex);
			}
		}
		if (slottable->st_thr_count == 0) {
			(void) pthread_mutex_unlock(&slottable->st_mutex);

			/* No more threads, no events found */
			pthread_exit(0);
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * child_waitforslotevent is used as a child thread to contact
 * underlying provider's C_WaitForSlotEvent().
 */
static void *
child_waitforslotevent(void *arg) {

	wfse_args_t *wfse = (wfse_args_t *)arg;
	CK_SLOT_ID slot;
	CK_RV rv;
	uint32_t cur_prov;
	CK_SLOT_ID i;

	rv = FUNCLIST(wfse->slotid)->C_WaitForSlotEvent(wfse->flags, &slot,
	    wfse->pReserved);

	/*
	 * Need to hold the mutex while processing the results, to
	 * keep things synchronized with the listener thread and
	 * the slottable.  Otherwise, due to the timing
	 * at which some underlying providers complete, the listener
	 * thread may not actually be blocking on st_wait_cond when
	 * this child signals.  Holding the lock a bit longer prevents
	 * this from happening.
	 */
	(void) pthread_mutex_lock(&slottable->st_mutex);

	while (slottable->st_list_signaled == B_TRUE) {
		/*
		 * We've taken the mutex when the listener should have
		 * control. Release the mutex, thread scheduler should
		 * give control back to the listener.
		 */
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		(void) sleep(1);
		(void) pthread_mutex_lock(&slottable->st_mutex);
	}

	if (rv == CKR_OK) {
		/* we've had an event, find slot and store it */
		cur_prov = slottable->st_slots[wfse->slotid]->sl_prov_id;

		/*
		 * It is safe to unset active status now, since call to
		 * underlying provider has already terminated, and we
		 * hold the slottable wide mutex (st_mutex).
		 */
		(void) pthread_mutex_lock(&slottable->
		    st_slots[wfse->slotid]->sl_mutex);

		slottable->st_slots[wfse->slotid]->sl_wfse_state = WFSE_CLEAR;

		(void) pthread_mutex_unlock(&slottable->
		    st_slots[wfse->slotid]->sl_mutex);


		for (i = wfse->slotid; i <= slottable->st_last; i++) {
			if (cur_prov != slottable->st_slots[i]->sl_prov_id) {
				break;
			}

			if (slot == slottable->st_slots[i]->sl_id) {
				(void) pthread_mutex_lock(&slottable->
				    st_slots[i]->sl_mutex);

				slottable->st_slots[i]->
				    sl_wfse_state = WFSE_EVENT;

				(void) pthread_mutex_unlock(&slottable->
				    st_slots[i]->sl_mutex);

				slottable->st_event_slot = i;

				if (slottable->st_blocking) {
					slottable->st_list_signaled = B_TRUE;
					(void) pthread_cond_signal(&slottable->
					    st_wait_cond);
				}

				(void) pthread_mutex_unlock(
					&slottable->st_mutex);

				pthread_exit(0);
			}
		}

	}

	(void) pthread_mutex_lock(&slottable->
	    st_slots[wfse->slotid]->sl_mutex);

	/*
	 * If the provider told us that it does not support
	 * this function, we should mark it so we do not waste
	 * time later with it.  If an error returned, we'll clean
	 * up this thread now and possibly try it again later.
	 */
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		slottable->st_slots[wfse->slotid]->sl_no_wfse = B_TRUE;
	}

	/*
	 * It is safe to unset active status now, since call to
	 * underlying provider has already terminated, and we
	 * hold the slottable wide mutex (st_mutex).
	 */
	slottable->st_slots[wfse->slotid]->sl_wfse_state = WFSE_CLEAR;
	(void) pthread_mutex_unlock(&slottable->
	    st_slots[wfse->slotid]->sl_mutex);


	if (slottable->st_blocking) {
		slottable->st_list_signaled = B_TRUE;
		(void) pthread_cond_signal(&slottable->st_wait_cond);
	}

	(void) pthread_mutex_unlock(&slottable->st_mutex);

	/* Manually exit the thread, since nobody will join to it */
	pthread_exit(0);

	/*NOTREACHED*/
	return (NULL);
}
