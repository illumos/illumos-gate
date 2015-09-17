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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KERNELGLOBAL_H
#define	_KERNELGLOBAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/crypto/common.h>
#include <security/cryptoki.h>
#include <security/pkcs11t.h>
#include "kernelObject.h"

typedef struct kmh_elem {
	CK_MECHANISM_TYPE type;
	crypto_mech_type_t kmech;	/* kCF mech number */
	struct kmh_elem *knext;		/* Next in hash chain */
} kmh_elem_t;

extern kmh_elem_t **kernel_mechhash;
extern boolean_t kernel_initialized;
extern int kernel_fd;

#define	KMECH_HASHTABLE_SIZE	67

#define	CRYPTO_DEVICE		"/dev/crypto"

/* CK_INFO: Information about cryptoki */
#define	CRYPTOKI_VERSION_MAJOR	2
#define	CRYPTOKI_VERSION_MINOR	40
#define	MANUFACTURER_ID		"Sun Microsystems, Inc.          "
#define	LIBRARY_DESCRIPTION	"Sun Crypto pkcs11_kernel        "
#define	LIBRARY_VERSION_MAJOR	1
#define	LIBRARY_VERSION_MINOR	1


/* CK_SLOT_INFO: Information about our slot */
#define	SLOT_DESCRIPTION	"Sun Crypto pkcs11_kernel        " \
				"                                "
#define	HARDWARE_VERSION_MAJOR	0
#define	HARDWARE_VERSION_MINOR	0
#define	FIRMWARE_VERSION_MAJOR	0
#define	FIRMWARE_VERSION_MINOR	0

#define	INPLACE_MECHANISM(m)	((m) == CKM_DES_ECB || (m) == CKM_DES_CBC || \
	(m) == CKM_DES3_ECB || (m) == CKM_DES3_CBC || (m) == CKM_AES_ECB || \
	(m) == CKM_AES_CBC || (m) == CKM_RC4 || (m) == CKM_BLOWFISH_CBC)

CK_RV crypto2pkcs11_error_number(uint_t);
CK_RV kernel_mech(CK_MECHANISM_TYPE, crypto_mech_type_t *);
unsigned char *get_symmetric_key_value(kernel_object_t *);
CK_RV get_rsa_public_key(kernel_object_t *, crypto_key_t *);
CK_RV get_rsa_private_key(kernel_object_t *, crypto_key_t *);
CK_RV get_dsa_public_key(kernel_object_t *, crypto_key_t *);
CK_RV get_dsa_private_key(kernel_object_t *, crypto_key_t *);
CK_RV get_ec_public_key(kernel_object_t *, crypto_key_t *);
CK_RV get_ec_private_key(kernel_object_t *, crypto_key_t *);
void free_key_attributes(crypto_key_t *);
void get_ulong_attr_from_template(CK_ULONG *, CK_ATTRIBUTE_PTR);
CK_RV process_object_attributes(CK_ATTRIBUTE_PTR, CK_ULONG, caddr_t *,
    CK_BBOOL *);
CK_RV get_object_attributes(CK_ATTRIBUTE_PTR, CK_ULONG, caddr_t);
void free_object_attributes(caddr_t, CK_ULONG);
CK_RV get_cka_private_value(kernel_session_t *, crypto_object_id_t,
    CK_BBOOL *);
CK_RV process_found_objects(kernel_session_t *, CK_OBJECT_HANDLE *,
    CK_ULONG *, crypto_object_find_update_t);
CK_RV get_mechanism_info(kernel_slot_t *, CK_MECHANISM_TYPE,
    CK_MECHANISM_INFO_PTR, uint32_t *);
CK_RV kernel_decrypt_init(kernel_session_t *, kernel_object_t *,
    CK_MECHANISM_PTR);
CK_RV kernel_decrypt(kernel_session_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
    CK_ULONG_PTR);
CK_RV kernel_add_extra_attr(CK_ATTRIBUTE_PTR, kernel_object_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _KERNELGLOBAL_H */
