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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983-1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SYS_DES_H
#define	_SYS_DES_H

/*
 * Generic DES driver interface
 * Keep this file hardware independent!
 */

#include <sys/ioccom.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DES_MAXLEN 	65536	/* maximum # of bytes to encrypt  */
#define	DES_QUICKLEN	16	/* maximum # of bytes to encrypt quickly */

enum desdir { ENCRYPT, DECRYPT };
enum desmode { CBC, ECB };

/*
 * parameters to ioctl call
 */
struct desparams {
	uchar_t des_key[8];	/* key (with low bit parity) */
	enum desdir des_dir;	/* direction */
	enum desmode des_mode;	/* mode */
	uchar_t des_ivec[8];	/* input vector */
	unsigned des_len;	/* number of bytes to crypt */
	union {
		uchar_t UDES_data[DES_QUICKLEN];
		uchar_t *UDES_buf;
	} UDES;
#define	des_data	UDES.UDES_data	/* direct data here if quick */
#define	des_buf		UDES.UDES_buf	/* otherwise, pointer to data */
};

/*
 * Encrypt an arbitrary sized buffer
 */
#define	DESIOCBLOCK	_IOWR('d', 6, struct desparams)

/*
 * Encrypt of small amount of data, quickly
 */
#define	DESIOCQUICK	_IOWR('d', 7, struct desparams)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DES_H */
