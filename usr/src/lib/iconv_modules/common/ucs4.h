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

#ifndef UCS4_H
#define UCS4_H
#include <sys/isa_defs.h>
#include <sys/types.h>
#include "ucs2.h"
#include "gentypes.h"

#define UCS4_NBYTE  4
#define UCS4_MAXVAL 0x7fffffff
#define UCS4_PPRC_MAXVAL 0xfffd	/* PPRC: Per Plane Row Column */

#define room_for_ucs4_cnv(p1,p2) 	(((p1)+sizeof(ucs4_t))<=(p2))
#define no_room_for_ucs4_cnv(p1,p2) 	(((p1)+sizeof(ucs4_t))>(p2))
#define incomplete_ucs4_seq(p1,p2) 	(((p1)+sizeof(ucs4_t))>(p2))

#define valid_ucs4_value(n) (_valid_ucs4_value(n))

#define ext_ucs4_lsw(n)	((ucs2_t)((((ucs4_t)(n))&((ucs4_t)0x0000ffff))))
#define ext_ucs4_msw(n)	((ucs2_t)((((ucs4_t)(n))&((ucs4_t)0xffff0000))>>16))

#define get_ucs4_word(p)        (*((ucs4_t*)(p)))
#define set_ucs4_word(p,n)	((*((ucs4_t*)(p)))=n)

#if defined(_BIG_ENDIAN)
#define get_ucs4_word_BB(p)	(((ucs4_t)(get_ucs2_word_BB((p))<<16))|\
				 ((ucs4_t)(get_ucs2_word_BB((p)+2))))

#define set_ucs4_word_BB(p,n) 	(set_ucs2_word_BB((p),ext_ucs4_msw(n)),\
				 set_ucs2_word_BB((p)+2,ext_ucs4_lsw(n)))
#else
#define get_ucs4_word_BB(p)	(((ucs4_t)(get_ucs2_word_BB((p)+2)<<16))|\
				 ((ucs4_t)(get_ucs2_word_BB(p))))

#define set_ucs4_word_BB(p,n) 	(set_ucs2_word_BB((p)+2,ext_ucs4_msw(n)),\
				 set_ucs2_word_BB((p),ext_ucs4_lsw(n)))
#endif

int _valid_ucs4_value(ucs4_t);
#endif
