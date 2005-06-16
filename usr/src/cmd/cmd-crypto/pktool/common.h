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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PKTOOL_COMMON_H
#define	_PKTOOL_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains data and functions shared between all the
 * modules that comprise this tool.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <cryptoutil.h>
#include <biginteger.h>

/* I18N helpers. */
#include <libintl.h>
#include <locale.h>

/* Defines used throughout */
#define	FULL_NAME_LEN	91	/* See full_token_name() for this number. */

/* Error codes */
#define	PK_ERR_NONE		0
#define	PK_ERR_USAGE		1
#define	PK_ERR_QUIT		2
#define	PK_ERR_PK11		3
#define	PK_ERR_SYSTEM		4
#define	PK_ERR_OPENSSL		5

/* Types of objects for searches. */
#define	PK_PRIVATE_OBJ		0x0001
#define	PK_PUBLIC_OBJ		0x0002
#define	PK_CERT_OBJ		0x0010
#define	PK_PRIKEY_OBJ		0x0020
#define	PK_PUBKEY_OBJ		0x0040
#define	PK_SECKEY_OBJ		0x0080

#define	PK_KEY_OBJ		(PK_PRIKEY_OBJ|PK_PUBKEY_OBJ|PK_SECKEY_OBJ)
#define	PK_ALL_OBJ		(PK_PRIVATE_OBJ|PK_PUBLIC_OBJ|\
				PK_CERT_OBJ|PK_KEY_OBJ)

/* Constants for attribute templates. */
extern CK_BBOOL	pk_false;
extern CK_BBOOL	pk_true;


/* Common functions. */
extern CK_RV	init_pk11(void);
extern void	final_pk11(CK_SESSION_HANDLE sess);

extern CK_RV	open_sess(CK_SLOT_ID slot_id, CK_FLAGS sess_flags,
		    CK_SESSION_HANDLE_PTR sess);
extern void	close_sess(CK_SESSION_HANDLE sess);

extern CK_RV	login_token(CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin,
		    CK_ULONG pinlen, CK_SESSION_HANDLE_PTR sess);
extern void	logout_token(CK_SESSION_HANDLE sess);

extern CK_RV	quick_start(CK_SLOT_ID slot_id, CK_FLAGS sess_flags,
		    CK_UTF8CHAR_PTR pin, CK_ULONG pinlen,
		    CK_SESSION_HANDLE_PTR sess);
extern void	quick_finish(CK_SESSION_HANDLE sess);

extern CK_RV	get_pin(char *prompt1, char *prompt2, CK_UTF8CHAR_PTR *pin,
		    CK_ULONG *pinlen);
extern boolean_t	yesno(char *prompt, char *invalid, boolean_t dflt);

extern CK_RV	get_token_slots(CK_SLOT_ID_PTR *slot_list,
		    CK_ULONG *slot_count);
extern CK_RV	find_token_slot(char *token_name, char *manuf_id,
		    char *serial_no, CK_SLOT_ID *slot_id, CK_FLAGS *pin_state);

extern CK_RV	find_obj_count(CK_SESSION_HANDLE sess, int obj_type,
		    CK_BYTE *label, CK_ULONG *count);
extern CK_RV	find_objs(CK_SESSION_HANDLE sess, int obj_type,
		    CK_BYTE *label, CK_OBJECT_HANDLE_PTR *obj, CK_ULONG *count);

extern void	full_token_name(char *token, char *manuf, char *serial,
		    char *buf);

extern char	*class_str(CK_OBJECT_CLASS class);
extern char	*keytype_str(CK_KEY_TYPE keytype);
extern char	*attr_str(CK_ATTRIBUTE_TYPE attrtype);

extern void	octetify(CK_BYTE *str, CK_ULONG str_sz, char *oct, int oct_sz,
		    boolean_t stop_on_nul, boolean_t do_ascii, int limit,
		    char *indent, char *blank);

extern void	copy_bigint_to_attr(biginteger_t big, CK_ATTRIBUTE_PTR attr);
extern void	copy_string_to_attr(CK_BYTE *buf, CK_ULONG buflen,
		    CK_ATTRIBUTE_PTR attr);
extern void	copy_attr_to_bigint(CK_ATTRIBUTE_PTR attr, biginteger_t *big);
extern void	copy_attr_to_string(CK_ATTRIBUTE_PTR attr, CK_BYTE **buf,
		    CK_ULONG *buflen);
extern void	copy_attr_to_date(CK_ATTRIBUTE_PTR attr, CK_DATE **buf,
		    CK_ULONG *buflen);

#ifdef __cplusplus
}
#endif

#endif /* _PKTOOL_COMMON_H */
