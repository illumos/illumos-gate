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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_WANBOOT_IMPL_H
#define	_SYS_WANBOOT_IMPL_H

#include <sys/types.h>
#include <aes.h>
#include <des3.h>
#include <hmac_sha1.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PKCS12 passphrase used by WAN boot
 */
#define	WANBOOT_PASSPHRASE	"boy with goldfish"

/*
 * Key names used by OBP.
 */
#define	WANBOOT_DES3_KEY_NAME		"wanboot-3des"
#define	WANBOOT_AES_128_KEY_NAME	"wanboot-aes"
#define	WANBOOT_HMAC_SHA1_KEY_NAME	"wanboot-hmac-sha1"
#define	WANBOOT_MAXKEYNAMELEN		sizeof (WANBOOT_HMAC_SHA1_KEY_NAME)

#define	WANBOOT_MAXKEYLEN	1024    /* sized for RSA */

#define	WANBOOT_MAXBLOCKLEN	AES_BLOCK_SIZE
#define	WANBOOT_HMAC_KEY_SIZE	20	/* size of key we use for HMAC SHA-1 */

struct wankeyio {
	char	wk_keyname[WANBOOT_MAXKEYNAMELEN];
	uint_t	wk_keysize;
	union {
		char	hmac_sha1_key[WANBOOT_HMAC_KEY_SIZE];
		char	des3key[DES3_KEY_SIZE];
		char	aeskey[AES_128_KEY_SIZE];
		char	key[WANBOOT_MAXKEYLEN];
	} wk_u;
};

#define	wk_hmac_sha1_key	wk_u.hmac_sha1_key
#define	wk_3des_key		wk_u.3des_key
#define	wk_aes_key		wk_u.aeskey

#define	WANBOOT_SETKEY		(('W' << 24) | ('A' << 16) | ('N' << 8) | 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WANBOOT_IMPL_H */
