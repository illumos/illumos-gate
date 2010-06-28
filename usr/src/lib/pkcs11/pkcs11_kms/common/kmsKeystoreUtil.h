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

#ifndef _KEYSTOREUTIL_H
#define	_KEYSTOREUTIL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "kmsSession.h"
#include "kmsObject.h"

CK_RV KMS_Initialize(void);
CK_RV KMS_Finalize();
CK_RV KMS_LoadProfile(KMSClientProfile *, kms_cfg_info_t *,
    const char *, size_t);
CK_RV KMS_GenerateKey(kms_session_t *, kms_object_t *);
CK_RV KMS_DestroyKey(kms_session_t *, kms_object_t *);
void KMS_UnloadProfile(KMSClientProfile *);
CK_RV KMS_RefreshObjectList(kms_session_t *, kms_slot_t *);
CK_RV KMS_ChangeLocalPWD(kms_session_t *, const char *, const char *);
CK_RV KMS_GetConfigInfo(kms_cfg_info_t *);

CK_BBOOL kms_is_initialized();
CK_BBOOL kms_is_pin_set();
CK_RV kms_reload_labels(kms_session_t *);
void kms_clear_label_list(avl_tree_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _KEYSTOREUTIL_H */
