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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef UCS2_H
#define UCS2_H
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "gentypes.h"

#define UCS2_NBYTE	2
#define UCS2_MAXVAL	0xfffd

#define valid_ucs2_value(n)		(_valid_ucs2_value(n))
#define room_for_ucs2_cnv(p1,p2)	(((p1)+sizeof(ucs2_t))<=(p2))
#define no_room_for_ucs2_cnv(p1,p2) 	(((p1)+sizeof(ucs2_t))>(p2))
#define incomplete_ucs2_seq(p1,p2) 	(((p1)+sizeof(ucs2_t))>(p2))

#define next_ucs2_ptr(p)    (((uchar_t*)(p))+sizeof(ucs2_t))
#define ext_ucs2_lsb(n)	    ((uchar_t)(((ucs2_t)(n))&((ucs2_t)0x00ff)))
#define ext_ucs2_msb(n)	    ((uchar_t)(((((ucs2_t)(n))&((ucs2_t)0xff00)))>>8))

#define get_ucs2_word(p)        (*((ucs2_t*)(p)))
#define set_ucs2_word(p,n)	((*((ucs2_t*)(p)))=(n))

#if defined(_BIG_ENDIAN)
#define get_ucs2_word_BB(p) \
	(((ucs2_t)((*(p))<<8))|((ucs2_t)(*((p)+1))))

#define set_ucs2_word_BB(p,n) \
	(((*(p))=ext_ucs2_msb(n)),((*((p)+1))=ext_ucs2_lsb(n)))

#else
#define get_ucs2_word_BB(p) \
	(((ucs2_t)(((*((p)+1)))<<8))|((ucs2_t)(*(p))))

#define set_ucs2_word_BB(p,n) \
	((*((p)+1))=ext_ucs2_msb(n),(*(p))=ext_ucs2_lsb(n))
#endif

int _valid_ucs2_value(ucs4_t);
#endif
