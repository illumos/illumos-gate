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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*        All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * des_crypt.h, des library routine interface
 */

#define	DES_MAXDATA 8192	/* max bytes encrypted in one call */
#define	DES_DIRMASK (1 << 0)
#define	DES_ENCRYPT (0*DES_DIRMASK)	/* Encrypt */
#define	DES_DECRYPT (1*DES_DIRMASK)	/* Decrypt */


#define	DES_DEVMASK (1 << 1)
#define	DES_HW (0*DES_DEVMASK)	/* Use hardware device */
#define	DES_SW (1*DES_DEVMASK)	/* Use software device */


#define	DESERR_NONE 0	/* succeeded */
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
int
cbc_crypt(/* key, buf, len, mode, ivec */); /*
	char *key;
	char *buf;
	unsigned len;
	unsigned mode;
	char *ivec;
*/


/*
 * Electronic Code Book mode
 */
int
ecb_crypt(/* key, buf, len, mode */); /*
	char *key;
	char *buf;
	unsigned len;
	unsigned mode;
*/


#ifndef KERNEL
/*
 * Set des parity for a key.
 * DES parity is odd and in the low bit of each byte
 */
void
des_setparity(/* key */); /*
	char *key;
*/
#endif
