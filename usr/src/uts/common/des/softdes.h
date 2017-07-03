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
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _SYS_SOFTDES_H
#define	_SYS_SOFTDES_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * softdes.h,  Data types and definition for software DES
 */

/*
 * A chunk is an area of storage used in three different ways
 * - As a 64 bit quantity (in high endian notation)
 * - As a 48 bit quantity (6 low order bits per byte)
 * - As a 32 bit quantity (first 4 bytes)
 */
typedef union {
	struct {
/*
 * This (and the one farther down) looks awfully backwards???
 */
#ifdef _LONG_LONG_LTOH
		uint32_t	_long1;
		uint32_t	_long0;
#else
		uint32_t	_long0;
		uint32_t	_long1;
#endif
	} _longs;

#define	long0	_longs._long0
#define	long1	_longs._long1
	struct {
#ifdef _LONG_LONG_LTOH
		uchar_t	_byte7;
		uchar_t	_byte6;
		uchar_t	_byte5;
		uchar_t	_byte4;
		uchar_t	_byte3;
		uchar_t	_byte2;
		uchar_t	_byte1;
		uchar_t	_byte0;
#else
		uchar_t	_byte0;
		uchar_t	_byte1;
		uchar_t	_byte2;
		uchar_t	_byte3;
		uchar_t	_byte4;
		uchar_t	_byte5;
		uchar_t	_byte6;
		uchar_t	_byte7;
#endif
	} _bytes;
#define	byte0	_bytes._byte0
#define	byte1	_bytes._byte1
#define	byte2	_bytes._byte2
#define	byte3	_bytes._byte3
#define	byte4	_bytes._byte4
#define	byte5	_bytes._byte5
#define	byte6	_bytes._byte6
#define	byte7	_bytes._byte7
} chunk_t;

/*
 * Intermediate key storage
 * Created by des_setkey, used by des_encrypt and des_decrypt
 * 16 48 bit values
 */
struct deskeydata {
	chunk_t	keyval[16];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOFTDES_H */
