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
 * Copyright(c) 2001 Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PC_ISCII_H_
#define _PC_ISCII_H_

#define uchar unsigned char

typedef struct _entry {
    uchar pc_iscii;
    uchar iscii;
    int   count;
} Entry;

Entry  pciscii_isc_tbl[] = {
    { 0x80, 0xA1, 48 },
    { 0xE0, 0xEF, 1  },
    { 0xE1, 0xD1, 15 },
    { 0xF0, 0xF0, 1  },
    { 0xF1, 0xE0, 11 }
};

Entry isc_pciscii_tbl[] = {
    { 0x80, 0xA1, 48 },
    { 0xE1, 0xD1, 15 },
    { 0xF1, 0xE0, 11 },
    { 0xE0, 0xEF, 1  },
    { 0xF0, 0xF0, 1  },
    { 0x30, 0xF1, 10 } /* convert Iscii numerals to ascii numerals */
};

#endif
