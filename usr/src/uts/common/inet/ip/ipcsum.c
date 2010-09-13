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
 * Copyright (c) 1992,1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/isa_defs.h>
#include <inet/common.h>

#define	FOLD_SUM(sum) \
{ sum = (sum >> 16) + (sum & 0xFFFF); sum = (sum >> 16) + (sum & 0xFFFF); }
#define	U16AM(p, i, m)	((((uint16_t *)(p))[i]) & (uint32_t)(m))

/*
 * For maximum efficiency, these access macros should be redone for
 * machines that can access unaligned data.  NOTE: these assume
 * ability to fetch from a zero extended 'uint8_t' and 'uint16_t'.  Add explicit
 * masks in the U8_FETCH, U16_FETCH, PREV_TWO and NEXT_TWO as needed.
 */

#ifdef	_LITTLE_ENDIAN
#define	U8_FETCH_FIRST(p)	((p)[0])
#define	U8_FETCH_SECOND(p)	(((uint32_t)(p)[0]) << 8)
#define	PREV_ONE(p)		U16AM(p, -1, 0xFF00)
#define	NEXT_ONE(p)		U16AM(p, 0, 0xFF)
#else
#define	U8_FETCH_FIRST(p)	((uint32_t)((p)[0]) << 8)
#define	U8_FETCH_SECOND(p)	((p)[0])
#define	PREV_ONE(p)		U16AM(p, -1, 0xFF)
#define	NEXT_ONE(p)		U16AM(p, 0, 0xFF00)
#endif

#define	U16_FETCH(p)		U8_FETCH_FIRST(p) + U8_FETCH_SECOND(p+1)
#define	PREV_TWO(p)		((uint32_t)(((uint16_t *)(p))[-1]))
#define	NEXT_TWO(p)		((uint32_t)(((uint16_t *)(p))[0]))

/*
 * Return the ones complement checksum from the mblk chain at mp,
 * after skipping offset bytes, and adding in the supplied partial
 * sum.  Note that a final complement of the return value is needed
 * if no further contributions to the checksum are forthcoming.
 */
uint16_t
ip_csum(mp, offset, sum)
	mblk_t *mp;
	int	offset;
	uint32_t	sum;
{
	uint8_t	*startp = mp->b_rptr + offset;
	uint8_t	*endp = mp->b_wptr;
/* >= 0x2 means flipped for memory align, 0x1 means last count was odd */
	int	odd_total = 0;

#ifdef	TEST_COVERAGE
	mblk_t *safe_mp;
#define	INIT_COVERAGE()	(safe_mp = mp, safe_mp->b_next = NULL)
#define	MARK_COVERAGE(flag) (safe_mp->b_next = \
	(mblk_t *)((uint32_t)safe_mp->b_next | flag))
#else
#define	INIT_COVERAGE()	/* */
#define	MARK_COVERAGE(flag)	/* */
#endif

	for (;;) {
		INIT_COVERAGE();
		if ((endp - startp) < 10) {
			MARK_COVERAGE(0x1);
			while ((endp - startp) >= 2) {
				MARK_COVERAGE(0x2);
				sum += U16_FETCH(startp);
				startp += 2;
			}
			if ((endp - startp) >= 1) {
				MARK_COVERAGE(0x4);
				odd_total = 1;
				sum += U8_FETCH_FIRST(startp);
			}
			MARK_COVERAGE(0x8);
			FOLD_SUM(sum);
			goto next_frag;
		}
		if ((uint32_t)startp & 0x1) {
			MARK_COVERAGE(0x10);
			odd_total = 3;
			startp++;
			sum = (sum << 8) + PREV_ONE(startp);
		}
		if ((uint32_t)startp & 0x2) {
			MARK_COVERAGE(0x20);
			startp += 2;
			sum += PREV_TWO(startp);
		}
		if ((uint32_t)endp & 0x1) {
			MARK_COVERAGE(0x40);
			odd_total ^= 0x1;
			endp--;
			sum += NEXT_ONE(endp);
		}
		if ((uint32_t)endp & 0x2) {
			MARK_COVERAGE(0x80);
			endp -= 2;
			sum += NEXT_TWO(endp);
		}

		{
#ifdef	NOT_ALL_PTRS_EQUAL
#define	INC_PTR(cnt)	ptr += cnt
#define	INC_ENDPTR(cnt)	endptr += cnt
			uint32_t	*ptr = (uint32_t *)startp;
			uint32_t	*endptr = (uint32_t *)endp;
#else
#define	INC_PTR(cnt)	startp += (cnt * sizeof (uint32_t))
#define	INC_ENDPTR(cnt)	endp += (cnt * sizeof (uint32_t))
#define	ptr		((uint32_t *)startp)
#define	endptr		((uint32_t *)endp)
#endif


#ifdef	USE_FETCH_AND_SHIFT
			uint32_t	u1, u2;
			uint32_t	mask = 0xFFFF;
#define	LOAD1(i)	u1 = ptr[i]
#define	LOAD2(i)	u2 = ptr[i]
#define	SUM1(i)		sum += (u1 & mask) + (u1 >> 16)
#define	SUM2(i)		sum += (u2 & mask) + (u2 >> 16)
#endif

#ifdef	USE_FETCH_AND_ADDC
			uint32_t	u1, u2;
#define	LOAD1(i)	u1 = ptr[i]
#define	LOAD2(i)	u2 = ptr[i]
#define	SUM1(i)		sum += u1
#define	SUM2(i)		sum += u2
#endif

#ifdef	USE_ADDC
#define	SUM1(i)		sum += ptr[i]
#endif

#ifdef	USE_POSTINC
#define	SUM1(i)		sum += *((uint16_t *)ptr)++; sum += *((uint16_t *)ptr)++
#undef	INC_PTR
#define	INC_PTR(i)	/* */
#endif

#ifndef	LOAD1
#define	LOAD1(i)	/* */
#endif

#ifndef	LOAD2
#define	LOAD2(i)	/* */
#endif

#ifndef	SUM2
#define	SUM2(i)		SUM1(i)
#endif

/* USE_INDEXING is the default */
#ifndef	SUM1
#define	SUM1(i)
	sum += ((uint16_t *)ptr)[i * 2]; sum += ((uint16_t *)ptr)[(i * 2) + 1]
#endif

		LOAD1(0);
		INC_ENDPTR(-8);
		if (ptr <= endptr) {
			MARK_COVERAGE(0x100);
			do {
				LOAD2(1); SUM1(0);
				LOAD1(2); SUM2(1);
				LOAD2(3); SUM1(2);
				LOAD1(4); SUM2(3);
				LOAD2(5); SUM1(4);
				LOAD1(6); SUM2(5);
				LOAD2(7); SUM1(6);
				LOAD1(8); SUM2(7);
				INC_PTR(8);
			} while (ptr <= endptr);
		}
#ifdef USE_TAIL_SWITCH
		switch ((endptr + 8) - ptr) {
		case 7:	LOAD2(6); SUM2(6);
		case 6:	LOAD2(5); SUM2(5);
		case 5:	LOAD2(4); SUM2(4);
		case 4:	LOAD2(3); SUM2(3);
		case 3:	LOAD2(2); SUM2(2);
		case 2:	LOAD2(1); SUM2(1);
		case 1:	SUM1(0);
		case 0:	break;
		}
#else
		INC_ENDPTR(4);
		if (ptr <= endptr) {
			MARK_COVERAGE(0x200);
			LOAD2(1); SUM1(0);
			LOAD1(2); SUM2(1);
			LOAD2(3); SUM1(2);
			LOAD1(4); SUM2(3);
			INC_PTR(4);
		}
		INC_ENDPTR(4);
		if (ptr < endptr) {
			MARK_COVERAGE(0x400);
			do {
				SUM1(0); LOAD1(1);
				INC_PTR(1);
			} while (ptr < endptr);
		}
#endif
		}

		FOLD_SUM(sum);
		if (odd_total > 1) {
			MARK_COVERAGE(0x800);
			sum = ((sum << 8) | (sum >> 8)) & 0xFFFF;
			odd_total -= 2;
		}
next_frag:
		mp = mp->b_cont;
		if (!mp) {
			MARK_COVERAGE(0x1000);
			{
			uint32_t	u1 = sum;
			return ((uint16_t)u1);
			}
		}
		MARK_COVERAGE(0x4000);
		startp = mp->b_rptr;
		endp = mp->b_wptr;
		if (odd_total && (endp > startp)) {
			MARK_COVERAGE(0x8000);
			odd_total = 0;
			sum += U8_FETCH_SECOND(startp);
			startp++;
		}
	}
}
#undef	endptr
#undef	INIT_COVERAGE
#undef	INC_PTR
#undef	INC_ENDPTR
#undef	LOAD1
#undef	LOAD2
#undef	MARK_COVERAGE
#undef	ptr
#undef	SUM1
#undef	SUM2



#undef	FOLD_SUM
#undef	NEXT_ONE
#undef	NEXT_TWO
#undef	PREV_ONE
#undef	PREV_TWO
#undef	U8_FETCH_FIRST
#undef	U8_FETCH_SECOND
#undef	U16AM
#undef	U16_FETCH
