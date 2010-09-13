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

#ifndef	_KERNEL_SLOT_H
#define	_KERNEL_SLOT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "kernelSession.h"
#include <sys/crypto/ioctl.h>

#define	CKU_PUBLIC	2	/* default session auth. state */

typedef struct cipher_mechs_threshold {
	int		mech_type;
	uint32_t	mech_threshold;
} cipher_mechs_threshold_t;

/*
 * This slot has limited hash support. It can not do multi-part
 * hashing (updates).
 */
#define	CRYPTO_LIMITED_HASH_SUPPORT	0x00000001

/*
 * This slot has limited hmac support. It can not do multi-part
 * hmac (updates).
 */
#define	CRYPTO_LIMITED_HMAC_SUPPORT	0x00000002

typedef struct kernel_slot {
	CK_SLOT_ID		sl_provider_id;	/* kernel provider ID */
	crypto_function_list_t	sl_func_list;	/* function list */
	kernel_session_t 	*sl_sess_list;	/* all open sessions */
	CK_USER_TYPE		sl_state;	/* session's auth. state */
	struct object 		*sl_tobj_list; 	/* token object list */
	pthread_mutex_t		sl_mutex;
	/*
	 * The valid values are defined above.
	 */
	uint32_t		sl_flags;

	/*
	 * The maximum input data that can be digested by this slot.
	 * Used only if CRYPTO_LIMITED_HASH_SUPPORT is set in sl_flags.
	 */
	int			sl_hash_max_inlen;

	/*
	 * The maximum input data that can be hmac'ed by this slot.
	 * Used only if CRYPTO_LIMITED_HMAC_SUPPORT is set in sl_flags.
	 */
	int			sl_hmac_max_inlen;

	/*
	 * The threshold for input data size. We use this slot
	 * only if data size is at or above this value. Used only if
	 * CRYPTO_LIMITED_HASH_SUPPORT or CRYPTO_LIMITED_HMAC_SUPPORT is set.
	 */
	int			sl_threshold;

	int total_threshold_count;
	cipher_mechs_threshold_t	sl_mechs_threshold[MAX_NUM_THRESHOLD];
} kernel_slot_t;

extern CK_ULONG slot_count;
extern kernel_slot_t **slot_table;

/*
 * Function Prototypes.
 */
CK_RV kernel_slottable_init();

#ifdef __cplusplus
}
#endif

#endif /* _KERNEL_SLOT_H */
