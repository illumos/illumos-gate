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

#ifndef _KMSGLOBAL_H
#define	_KMSGLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/crypto/common.h>
#include <security/cryptoki.h>
#include <security/pkcs11t.h>
#include "kmsObject.h"

typedef struct kms_elem {
	CK_MECHANISM_TYPE type;
	struct kms_elem *knext;		/* Next in hash chain */
} kms_elem_t;

extern kms_elem_t **kms_mechhash;
extern boolean_t kms_initialized;

#define	KMECH_HASHTABLE_SIZE	67

/* CK_INFO: Information about cryptoki */
#define	CRYPTOKI_VERSION_MAJOR	2
#define	CRYPTOKI_VERSION_MINOR	20
#define	MANUFACTURER_ID		"Oracle Corporation     "
#define	LIBRARY_DESCRIPTION	"Oracle Key Management System    "
#define	LIBRARY_VERSION_MAJOR	1
#define	LIBRARY_VERSION_MINOR	0

/* CK_SLOT_INFO: Information about our slot */
#define	SLOT_DESCRIPTION	"Oracle Key Management System    " \
				"                                "
#define	KMS_TOKEN_LABEL		"KMS                             "
#define	KMS_TOKEN_MODEL		"                "
#define	KMS_TOKEN_SERIAL	"                "
#define	KMS_TOKEN_FLAGS		CKF_LOGIN_REQUIRED
#define	MAX_PIN_LEN		256
#define	MIN_PIN_LEN		1
#define	HARDWARE_VERSION_MAJOR	0
#define	HARDWARE_VERSION_MINOR	0
#define	FIRMWARE_VERSION_MAJOR	0
#define	FIRMWARE_VERSION_MINOR	0

CK_RV crypto2pkcs11_error_number(uint_t);
CK_RV kms_mech(CK_MECHANISM_TYPE);
unsigned char *get_symmetric_key_value(kms_object_t *);
void free_key_attributes();

CK_RV process_object_attributes(CK_ATTRIBUTE_PTR, CK_ULONG, caddr_t *,
    CK_BBOOL *);
CK_RV get_object_attributes(CK_ATTRIBUTE_PTR, CK_ULONG, caddr_t);
void free_object_attributes(caddr_t, CK_ULONG);
CK_RV process_found_objects(kms_session_t *, CK_OBJECT_HANDLE *,
    CK_ULONG *);
CK_RV get_mechanism_info(kms_slot_t *, CK_MECHANISM_TYPE,
    CK_MECHANISM_INFO_PTR, uint32_t *);
CK_RV kms_add_extra_attr(CK_ATTRIBUTE_PTR, kms_object_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _KMSGLOBAL_H */
