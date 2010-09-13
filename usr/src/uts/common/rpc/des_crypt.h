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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * des_crypt.h, des library routine interface
 */

#ifndef _DES_DES_CRYPT_H
#define	_DES_DES_CRYPT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	DES_MAXDATA 8192	/* max bytes encrypted in one call */
#define	DES_DIRMASK (1 << 0)
#define	DES_ENCRYPT (0 * DES_DIRMASK)	/* Encrypt */
#define	DES_DECRYPT (1 * DES_DIRMASK)	/* Decrypt */


#define	DES_DEVMASK (1 << 1)
#define	DES_HW (0 * DES_DEVMASK)	/* Use hardware device */
#define	DES_SW (1 * DES_DEVMASK)	/* Use software device */


#define	DESERR_NONE 0		/* succeeded */
#define	DESERR_NOHWDEVICE 1	/* succeeded, but hw device not available */
#define	DESERR_HWERROR 2	/* failed, hardware/driver error */
#define	DESERR_BADPARAM 3	/* failed, bad parameter to call */

#define	DES_FAILED(err) \
	((err) > DESERR_NOHWDEVICE)

/*
 * cbc_crypt()
 * ecb_crypt()
 *
 * Encrypt (or decrypt) len bytes of a buffer buf.
 * The length must be a multiple of eight.
 * The key should have odd parity in the low bit of each byte.
 * ivec is the input vector, and is updated to the new one (cbc only).
 * The mode is created by oring together the appropriate parameters.
 * DESERR_NOHWDEVICE is returned if DES_HW was specified but
 * there was no hardware to do it on (the data will still be
 * encrypted though, in software).
 */


/*
 * Cipher Block Chaining mode
 */
#ifdef __STDC__
int cbc_crypt(char *key, char *buf, size_t len, unsigned int mode, char *ivec);
#else
int cbc_crypt();
#endif


/*
 * Electronic Code Book mode
 */
#ifdef __STDC__
int ecb_crypt(char *key, char *buf, size_t len, unsigned int mode);
#else
int ecb_crypt();
#endif


#ifndef _KERNEL
/*
 * Set des parity for a key.
 * DES parity is odd and in the low bit of each byte
 */
#ifdef __STDC__
void des_setparity(char *key);
#else
void des_setparity();
#endif
#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _DES_DES_CRYPT_H */
