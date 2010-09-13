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
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_KMS_SLOT_H
#define	_KMS_SLOT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "kmsSession.h"

#define	CKU_PUBLIC	2	/* default session auth. state */

typedef struct kms_slot {
	CK_SLOT_ID		sl_provider_id;	/* kernel provider ID */
	kms_session_t 		*sl_sess_list;	/* all open sessions */
	CK_USER_TYPE		sl_state;	/* session's auth. state */
	struct object 		*sl_tobj_list; 	/* token object list */
	pthread_mutex_t		sl_mutex;

	/*
	 * The valid values are defined above.
	 */
	uint32_t		sl_flags;
	int			total_threshold_count;
} kms_slot_t;

#define	KMS_TOKEN_SLOTID 1
#define	KMS_SLOTS	1

/*
 * Function Prototypes.
 */
CK_RV kms_slottable_init();
void cleanup_slottable();
kms_slot_t *get_slotinfo();

#ifdef __cplusplus
}
#endif

#endif /* _KMS_SLOT_H */
