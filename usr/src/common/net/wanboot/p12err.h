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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_P12ERR_H
#define	_P12ERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern void ERR_load_SUNW_strings(void);
extern void ERR_SUNW_error(int function, int reason, char *file, int line);

#define	SUNW_LIB_NAME	"SUNW_PKCS12"
#define	SUNWerr(f, r)	ERR_SUNW_error((f), (r), __FILE__, __LINE__)

/* Error codes for the SUNW functions. */
/* OpenSSL prefers codes to start at 100 */

/* Function codes. */
typedef enum {
	SUNW_F_USE_X509CERT = 100,
	SUNW_F_USE_PKEY,
	SUNW_F_USE_TASTORE,
	SUNW_F_USE_CERTFILE,
	SUNW_F_USE_KEYFILE,
	SUNW_F_USE_TRUSTFILE,
	SUNW_F_READ_FILE,
	SUNW_F_DOPARSE,
	SUNW_F_PKCS12_PARSE,
	SUNW_F_PKCS12_CONTENTS,
	SUNW_F_PARSE_ONE_BAG,
	SUNW_F_PKCS12_CREATE,
	SUNW_F_SPLIT_CERTS,
	SUNW_F_FIND_LOCALKEYID,
	SUNW_F_SET_LOCALKEYID,
	SUNW_F_GET_LOCALKEYID,
	SUNW_F_GET_PKEY_FNAME,
	SUNW_F_APPEND_KEYS,
	SUNW_F_PEM_CONTENTS,
	SUNW_F_PEM_INFO,
	SUNW_F_ASC2BMPSTRING,
	SUNW_F_UTF82ASCSTR,
	SUNW_F_FINDATTR,
	SUNW_F_TYPE2ATTRIB,
	SUNW_F_MOVE_CERTS,
	SUNW_F_FIND_FNAME,
	SUNW_F_PARSE_OUTER,
	SUNW_F_CHECKFILE
} sunw_err_func_t;

/* Reason codes. */
typedef enum {
	SUNW_R_INVALID_ARG = 100,
	SUNW_R_MEMORY_FAILURE,
	SUNW_R_MAC_VERIFY_FAILURE,
	SUNW_R_MAC_CREATE_FAILURE,
	SUNW_R_BAD_FILETYPE,
	SUNW_R_BAD_PKEY,
	SUNW_R_BAD_PKEYTYPE,
	SUNW_R_PKEY_READ_ERR,
	SUNW_R_NO_TRUST_ANCHOR,
	SUNW_R_READ_TRUST_ERR,
	SUNW_R_ADD_TRUST_ERR,
	SUNW_R_PKCS12_PARSE_ERR,
	SUNW_R_PKCS12_CREATE_ERR,
	SUNW_R_PARSE_BAG_ERR,
	SUNW_R_MAKE_BAG_ERR,
	SUNW_R_BAD_CERTTYPE,
	SUNW_R_PARSE_CERT_ERR,
	SUNW_R_BAD_LKID,
	SUNW_R_SET_LKID_ERR,
	SUNW_R_BAD_FNAME,
	SUNW_R_SET_FNAME_ERR,
	SUNW_R_BAD_TRUST,
	SUNW_R_BAD_BAGTYPE,
	SUNW_R_CERT_ERR,
	SUNW_R_PKEY_ERR,
	SUNW_R_READ_ERR,
	SUNW_R_ADD_ATTR_ERR,
	SUNW_R_STR_CONVERT_ERR,
	SUNW_R_PKCS12_EMPTY_ERR,
	SUNW_R_PASSWORD_ERR
} sunw_err_reason_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _P12ERR_H */
