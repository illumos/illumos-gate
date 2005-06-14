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

#include <dlfcn.h>
#include <stdlib.h>
#include <pthread.h>
#include <strings.h>
#include <security/cryptoki.h>
#include "pkcs11Global.h"
#include "pkcs11Slot.h"
#include "metaGlobal.h"

pkcs11_slottable_t *slottable = NULL;

/*
 * pkcs11_slottable_initialize initizializes the global slottable.
 * This slottable will contain information about the plugged in
 * slots, including their mapped slotID.  This function should only
 * be called by C_Intialize.
 */
CK_RV
pkcs11_slottable_initialize() {


	pkcs11_slottable_t *stmp = malloc(sizeof (pkcs11_slottable_t));

	if (stmp == NULL)
		return (CKR_HOST_MEMORY);

	stmp->st_first = 1;
	stmp->st_cur_size = 0;
	stmp->st_last = 0;
	stmp->st_slots = NULL;

	if (pthread_mutex_init(&stmp->st_mutex, NULL) != 0) {
		free(stmp);
		return (CKR_FUNCTION_FAILED);
	}
	/* Set up for possible threads later */
	stmp->st_event_slot = 0;
	stmp->st_thr_count = 0;
	stmp->st_wfse_active = B_FALSE;
	stmp->st_blocking = B_FALSE;
	stmp->st_list_signaled = B_FALSE;

	(void) pthread_cond_init(&stmp->st_wait_cond, NULL);
	(void) pthread_mutex_init(&stmp->st_start_mutex, NULL);
	(void) pthread_cond_init(&stmp->st_start_cond, NULL);

	slottable = stmp;

	return (CKR_OK);

}

/*
 * pkcs11_slottable_increase should only be called from C_Initialize().
 * It is called after the first call to C_GetSlotList() and is used to
 * increase the size of the slottable, as needed, to contain the next
 * set of slots that C_Initialize() is currently mapping into the framework.
 */
CK_RV
pkcs11_slottable_increase(ulong_t increment) {

	pkcs11_slot_t **tmpslots;
	ulong_t newsize;

	(void) pthread_mutex_lock(&slottable->st_mutex);

	/* Add 1 to cover space for the metaslot */
	newsize = slottable->st_last + increment + 1;

	/* Check to see if we already have enough space */
	if (slottable->st_cur_size >= newsize) {
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_OK);
	}

	tmpslots = realloc
	    (slottable->st_slots, newsize * sizeof (pkcs11_slot_t *));

	if (tmpslots == NULL) {
		(void) pthread_mutex_unlock(&slottable->st_mutex);
		return (CKR_HOST_MEMORY);
	}

	slottable->st_slots = tmpslots;
	slottable->st_cur_size = newsize;

	(void) pthread_mutex_unlock(&slottable->st_mutex);

	return (CKR_OK);
}

/*
 * pkcs11_slot_allocate should only be called from C_Initialize().
 * We won't know if the metaslot will be used until after all of
 * the other slots have been allocated.
 */
CK_RV
pkcs11_slot_allocate(CK_SLOT_ID *pslot_id) {

	pkcs11_slot_t *tmpslot;

	tmpslot = malloc(sizeof (pkcs11_slot_t));

	if (tmpslot == NULL)
		return (CKR_HOST_MEMORY);

	bzero(tmpslot, sizeof (pkcs11_slot_t));

	tmpslot->sl_wfse_state = WFSE_CLEAR;
	tmpslot->sl_enabledpol = B_FALSE;
	tmpslot->sl_no_wfse = B_FALSE;

	/* Initialize this slot's mutex */
	if (pthread_mutex_init(&tmpslot->sl_mutex, NULL) != 0) {
		free(tmpslot);
		return (CKR_FUNCTION_FAILED);
	}

	(void) pthread_mutex_lock(&slottable->st_mutex);

	slottable->st_last++;

	*pslot_id = slottable->st_last;

	slottable->st_slots[*pslot_id] = tmpslot;

	(void) pthread_mutex_unlock(&slottable->st_mutex);

	return (CKR_OK);

}

/*
 * pkcs11_slottable_delete should only be called by C_Finalize(),
 * or by C_Initialize() in error conditions.
 */
CK_RV
pkcs11_slottable_delete() {

	ulong_t i;
	uint32_t prov_id;
	int32_t last_prov_id = -1;
	pkcs11_slot_t *cur_slot;

	(void) pthread_mutex_lock(&slottable->st_mutex);

	for (i = slottable->st_first; i <= slottable->st_last; i++) {

		if (slottable->st_slots[i] != NULL) {

			cur_slot = slottable->st_slots[i];
			prov_id = cur_slot->sl_prov_id;

			(void) pthread_mutex_lock(&cur_slot->sl_mutex);

			/*
			 * For the first slot from this provider, do
			 * extra cleanup.
			 */
			if (prov_id != last_prov_id) {

				if (cur_slot->sl_wfse_state == WFSE_ACTIVE) {
					(void) pthread_cancel
					    (cur_slot->sl_tid);
				}

				/*
				 * Only call C_Finalize of plug-in if we
				 * get here from an explicit C_Finalize
				 * call from an application.  Otherwise,
				 * there is a risk that the application may
				 * have directly dlopened this provider and
				 * we could interrupt their work.  Plug-ins
				 * should have their own _fini function to
				 * clean up when they are no longer referenced.
				 */
				if ((cur_slot->sl_func_list != NULL) &&
				    (!fini_called)) {
					(void) cur_slot->
					    sl_func_list->C_Finalize(NULL);
				}
				(void) dlclose(cur_slot->sl_dldesc);
			}

			if (cur_slot->sl_pol_mechs != NULL) {
				free(cur_slot->sl_pol_mechs);
			}

			if (cur_slot->sl_wfse_args != NULL) {
				free(cur_slot->sl_wfse_args);
			}

			(void) pthread_mutex_unlock(&cur_slot->sl_mutex);

			/*
			 * Cleanup the session list.  This must
			 * happen after the mutext is unlocked
			 * because session_delete tries to lock it
			 * again.
			 */
			pkcs11_sessionlist_delete(cur_slot);

			(void) pthread_mutex_destroy(&cur_slot->sl_mutex);

			free(cur_slot);
			cur_slot = NULL;
			last_prov_id = prov_id;
		}
	}

	(void) pthread_cond_destroy(&slottable->st_wait_cond);
	(void) pthread_mutex_destroy(&slottable->st_start_mutex);
	(void) pthread_cond_destroy(&slottable->st_start_cond);

	free(slottable->st_slots);

	(void) pthread_mutex_unlock(&slottable->st_mutex);

	(void) pthread_mutex_destroy(&slottable->st_mutex);

	free(slottable);

	slottable = NULL;

	return (CKR_OK);

}

/*
 * pkcs11_is_valid_slot verifies that the slot ID passed to the
 * framework is valid.
 */
CK_RV
pkcs11_is_valid_slot(CK_SLOT_ID slot_id) {

	if ((slot_id < slottable->st_first) ||
	    (slot_id > slottable->st_last)) {
		return (CKR_SLOT_ID_INVALID);
	} else if (slottable->st_slots[slot_id] != NULL) {
		return (CKR_OK);
	} else {
		return (CKR_SLOT_ID_INVALID);
	}
}


/*
 * pkcs11_validate_and_convert_slotid verifies whether the slot ID
 * passed to the framework is valid, and convert it to the
 * true slot ID maintained in the framework data structures
 * accordingly.
 *
 * This is necessary because when metaslot is enabled, the slot
 * providing persistent object storage is "hidden".
 *
 * The real ID is returned in the "real_slot_id" argument regardless conversion
 * is done or not.
 */
CK_RV
pkcs11_validate_and_convert_slotid(CK_SLOT_ID slot_id,
    CK_SLOT_ID *real_slot_id) {

	if (!metaslot_enabled) {
		*real_slot_id = slot_id;
	} else {
		/* need to do conversion */
		if (slot_id >= metaslot_keystore_slotid) {
			*real_slot_id = slot_id + 1;
		} else {
			*real_slot_id = slot_id;
		}
	}
	return (pkcs11_is_valid_slot(*real_slot_id));
}
