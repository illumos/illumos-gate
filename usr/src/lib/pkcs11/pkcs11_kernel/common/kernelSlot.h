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

#ifndef	_KERNEL_SLOT_H
#define	_KERNEL_SLOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "kernelSession.h"
#include <sys/crypto/ioctl.h>

#define	CKU_PUBLIC	2	/* default session auth. state */

typedef struct kernel_slot {
	CK_SLOT_ID		sl_provider_id;	/* kernel provider ID */
	crypto_function_list_t	sl_func_list;	/* function list */
	kernel_session_t 	*sl_sess_list;	/* all open sessions */
	CK_USER_TYPE		sl_state;	/* session's auth. state */
	struct object 		*sl_tobj_list; 	/* token object list */
	pthread_mutex_t		sl_mutex;
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
