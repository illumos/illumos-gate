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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <security/cryptoki.h>
#include "kmsGlobal.h"
#include "kmsSlot.h"

static kms_slot_t	*slotinfo = NULL;

/*
 * Initialize the slotinfo record.
 *
 * This function is called from C_Initialize() only.  Since C_Initialize()
 * holds the global mutex lock, there is no need to acquire another lock
 * in this routine to protect the slot table.
 */
CK_RV
kms_slottable_init()
{
	CK_RV rv = CKR_OK;

	/* Allocate space for the slot table */
	slotinfo = calloc(KMS_SLOTS, sizeof (kms_slot_t));
	if (slotinfo == NULL)
		return (CKR_HOST_MEMORY);

	slotinfo->sl_sess_list = NULL;
	slotinfo->sl_tobj_list = NULL;
	slotinfo->sl_state = CKU_PUBLIC;

	/* Initialize this slot's mutex */
	if (pthread_mutex_init(&slotinfo->sl_mutex, NULL) != 0) {
		(void) free(slotinfo);
		slotinfo = NULL;
		return (CKR_FUNCTION_FAILED);
	}

	return (rv);
}

void
cleanup_slottable()
{
	if (slotinfo != NULL) {
		(void) pthread_mutex_destroy(&slotinfo->sl_mutex);
		(void) free(slotinfo);
		slotinfo = NULL;
	}
}

kms_slot_t *
get_slotinfo()
{
	return (slotinfo);
}
