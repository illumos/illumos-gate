/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 */


#ifndef _COMMON_THAI_H_
#define	_COMMON_THAI_H_

#include <sys/isa_defs.h>

#ifdef	_BIG_ENDIAN

typedef union {
        unsigned int code;
        struct {
                unsigned short high;
                unsigned short low;
        } word;
        struct {
                unsigned char byte1;
                unsigned char byte2;
                unsigned char byte3;
                unsigned char byte4;
        } byte;
        struct {
                unsigned int    high16bits:     16;	/* should be 0x00 */
                unsigned int    msb1:           1;	/* should be 0x01 */
                unsigned int    data1:       	7;
                unsigned int    msb2:           1;	/* should be 0x01 */
                unsigned int    data2:       	7;
        } eucTH;
        struct {
                unsigned int    high16bits:     16;	/* should be 0x00 */
                unsigned int    data1:          4;
                unsigned int    data2:          6;
                unsigned int    data3:          6;
        } unicode;
        struct {
                unsigned int    high8bits:      8;	/* should be 0x00 */
                unsigned int    sign1:          4;	/* should be 0x0E */
                unsigned int    data1:          4;
                unsigned int    sign2:          2;	/* should be 0x02 */
                unsigned int    data2:          6;
                unsigned int    sign3:          2;	/* should be 0x02 */
                unsigned int    data3:          6;
        } utf8;
} hcode_type;

#else /* _BIG_ENDIAN */

typedef union {
        unsigned int code;
        struct {
                unsigned short low;
                unsigned short high;
        } word;
        struct {
                unsigned char byte4;
                unsigned char byte3;
                unsigned char byte2;
                unsigned char byte1;
        } byte;
        struct {
                unsigned int    data2:       	7;
                unsigned int    msb2:           1;	/* should be 0x01 */
                unsigned int    data1:       	7;
                unsigned int    msb1:           1;	/* should be 0x01 */
                unsigned int    high16bits:     16;	/* should be 0x00 */
        } eucTH;
        struct {
                unsigned int    data3:          6;
                unsigned int    data2:          6;
                unsigned int    data1:          4;
                unsigned int    high16bits:     16;	/* should be 0x00 */
        } unicode;
        struct {
                unsigned int    data3:          6;
                unsigned int    sign3:          2;	/* should be 0x02 */
                unsigned int    data2:          6;
                unsigned int    sign2:          2;	/* should be 0x02 */
                unsigned int    data1:          4;
                unsigned int    sign1:          4;	/* should be 0x0E */
                unsigned int    high8bits:      8;	/* should be 0x00 */
        } utf8;
} hcode_type;

#endif /* _BIG_ENDIAN */

#endif	/* _COMMON_THAI_H_ */
