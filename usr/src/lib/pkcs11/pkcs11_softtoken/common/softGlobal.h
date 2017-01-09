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

#ifndef _SOFTGLOBAL_H
#define	_SOFTGLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <security/cryptoki.h>
#include <security/pkcs11t.h>

/*
 * The following global variables are defined in softGeneral.c
 */
extern boolean_t softtoken_initialized;
extern pthread_mutex_t soft_giant_mutex;
extern struct slot soft_slot;
extern struct obj_to_be_freed_list obj_delay_freed;
extern struct ses_to_be_freed_list ses_delay_freed;

#define	SOFTTOKEN_SLOTID	1

/* CK_INFO: Information about cryptoki */
#define	CRYPTOKI_VERSION_MAJOR	2
#define	CRYPTOKI_VERSION_MINOR	40
#define	LIBRARY_DESCRIPTION	"Sun Crypto Softtoken            "
#define	LIBRARY_VERSION_MAJOR	1
#define	LIBRARY_VERSION_MINOR	1


/* CK_SLOT_INFO: Information about our slot */
#define	HARDWARE_VERSION_MAJOR	0
#define	HARDWARE_VERSION_MINOR	0
#define	FIRMWARE_VERSION_MAJOR	0
#define	FIRMWARE_VERSION_MINOR	0

/* CK_TOKEN_INFO: More information about token */
#define	TOKEN_MODEL		"1.0             "
#define	MAX_PIN_LEN		256
#define	MIN_PIN_LEN		1

#define	SOFT_TOKEN_FLAGS	CKF_RNG|\
				CKF_USER_PIN_INITIALIZED|\
				CKF_LOGIN_REQUIRED|\
				CKF_RESTORE_KEY_NOT_NEEDED|\
				CKF_DUAL_CRYPTO_OPERATIONS|\
				CKF_TOKEN_INITIALIZED

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTGLOBAL_H */
