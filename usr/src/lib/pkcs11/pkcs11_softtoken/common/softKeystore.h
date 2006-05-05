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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOFTKEYSTORE_H
#define	_SOFTKEYSTORE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>

#define	PBKD2_SALT_SIZE	16
#define	PBKD2_ITERATIONS (1000)
#define	PWD_BUFFER_SIZE	1024

/*
 * The following structure is the object header
 * in the keystore.
 */
typedef struct ks_obj_hdr {
	uint64_t class;
	uint64_t key_type;
	uint64_t cert_type;
	uint64_t bool_attr_mask;
	uint64_t mechanism;
	uchar_t object_type;

	/* Extra non-boolean attribute list */
	int	num_attrs;
} ks_obj_hdr_t;

/*
 * This structure contains the individual attribute
 * (from extra_attrlistp) in the keystore.
 */
typedef struct ks_attr_hdr {
	uint64_t type;
	uint64_t ulValueLen;
} ks_attr_hdr_t;

#define	ROUNDUP(x, y)	roundup(x, y)	/* defined in sys/sysmacros.h */

#ifdef _LITTLE_ENDIAN
#define	SWAP16(value)  \
	((((value) & 0xff) << 8) | ((value) >> 8))

#define	SWAP32(value)	\
	(((uint32_t)SWAP16((uint16_t)((value) & 0xffff)) << 16) | \
	(uint32_t)SWAP16((uint16_t)((value) >> 16)))

#define	SWAP64(value)	\
	(((uint64_t)SWAP32((uint32_t)((value) & 0xffffffff)) \
	    << 32) | \
	(uint64_t)SWAP32((uint32_t)((value) >> 32)))
#else /* !_LITTLE_ENDIAN */
#define	SWAP16(value)	(value)
#define	SWAP32(value)	(value)
#define	SWAP64(value)	(value)
#endif

/*
 * Function Prototypes
 */
CK_RV soft_gen_iv(CK_BYTE *iv);

int soft_gen_hashed_pin(CK_UTF8CHAR_PTR pPin, char **result, char **salt);

CK_RV soft_verify_pin(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

CK_RV soft_gen_crypt_key(uchar_t *pPIN, soft_object_t **key,
	CK_BYTE **saltdata);

CK_RV soft_gen_hmac_key(uchar_t *pPIN, soft_object_t **key, CK_BYTE **saltdata);

CK_RV soft_keystore_pack_obj(struct object *obj, uchar_t **ks_buf, size_t *len);

CK_RV soft_keystore_unpack_obj(struct object *obj, ks_obj_t *ks_obj);

CK_RV soft_unpack_obj_attribute(uchar_t *buf, biginteger_t *key_dest,
	cert_attr_t **cert_dest, ulong_t *offset, boolean_t cert);

ulong_t soft_pack_object_size(struct object *objp);

CK_RV soft_pack_object(struct object *objp, uchar_t *buf);

CK_RV soft_unpack_object(struct object *objp, uchar_t *buf);

CK_RV soft_setpin(CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen,
	CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen);

CK_RV soft_put_object_to_keystore(struct object *objp);

CK_RV soft_modify_object_to_keystore(struct object *objp);

CK_RV soft_get_token_objects_from_keystore(ks_search_type_t type);

CK_RV soft_init_token_session(void);

void soft_destroy_token_session(void);

CK_RV soft_keystore_crypt(soft_object_t *key_p, uchar_t *ivec,
	boolean_t encrypt, CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out,
	CK_ULONG_PTR out_len);

CK_RV soft_keystore_hmac(soft_object_t *key_p, boolean_t sign,
	CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG_PTR out_len);


#ifdef	__cplusplus
}
#endif

#endif /* _SOFTKEYSTORE_H */
