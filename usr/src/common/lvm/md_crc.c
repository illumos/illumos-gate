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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>

static uint_t		*mddb_crctab = NULL;

#ifndef _KERNEL
#include <meta.h>
#include <assert.h>
#define	MD_ZALLOC(x)	Zalloc(x)
#define	MD_FREE(x, y)	Free(x)
#else	/* _KERNEL */
#define	MD_ZALLOC(x)	kmem_zalloc(x, KM_SLEEP)
#define	MD_FREE(x, y)	kmem_free(x, y)
#include <sys/thread.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#endif	/* ! _KERNEL */
#include <sys/lvm/md_crc.h>

#define	MDDB_CRCMAGIC 987654

static uint_t *
crcgentab(void)
{
	int	b, i;
	uint_t		v;
	uint_t		*crctab;
	uint_t		poly = 0x04c11db7;

	crctab = (uint_t *)MD_ZALLOC(256 * sizeof (int));
	for (b = 0; b < 256; b++) {
		for (v = b << (24), i = 0; i < 8; i++) {
			if (v & ((unsigned int)1 << 31)) {
				v = (v << 1) ^ poly;
			} else {
				v = v << 1;
			}
		}
		crctab[b] = v;
	}
	return (crctab);
}

/*
 * crc function that allows  a number of areas to be skipped (ignored)
 * during the crc computation.  The result area of the record is also ignored
 * during the crc computation.  Ignored areas are used for data that may
 * be changed after record has been crcgen'd, but before the data has been
 * written to disk or for when a multi-owner diskset may have multiple
 * nodes writing the same record data with the exception of the timestamp field.
 * The list of skip areas must be in ascending order of offset and if any
 * areas overlap, the list will be modified.
 */
uint_t
crcfunc(
	uint_t	check,
	uchar_t *record,	/* record to be check-summed */
	uint_t	*result,	/* put check-sum here(really u_long) */
	size_t	size,		/* size of record in bytes */
	crc_skip_t *skip	/* list of areas to skip */
)
{
	uint_t		newcrc;
	uint_t		*crctab;
	uchar_t		*recaddr;
	crc_skip_t	*s, *p;

	/*
	 * Check skip areas to see if they overlap (this should never happen,
	 * but is handled just in case something changes in the future).
	 * Also the skip list must be in ascending order of offset, assert
	 * error if this is not the case.
	 * If any 2 adjacent skip areas overlap, then the skip areas will
	 * be merged into 1 skip area and the other skip area is freed.
	 * If any 2 adjacent skip areas abut (border) each other, then skip
	 * areas are not merged, but are left as 2 independent skip areas.
	 * If the skip areas are identical, no change is made to either skip
	 * area since this is handled later.
	 */
	if (skip) {
		p = NULL;
		for (s = skip; s != NULL; s = s->skip_next) {
			if (p == NULL) {
				p = s;
				continue;
			}
#ifdef _KERNEL
			ASSERT(s->skip_offset > p->skip_offset);
#else
			assert(s->skip_offset > p->skip_offset);
#endif
			if ((p->skip_offset + p->skip_size) > s->skip_offset) {
				/*
				 * Current area overlaps previous, modify
				 * previous area and release current
				 */
				p->skip_size += s->skip_size - (p->skip_offset
				    + p->skip_size - s->skip_offset);
				p->skip_next = s->skip_next;
				MD_FREE(s, sizeof (crc_skip_t));
				s = p;
			}
			p = s;
		}
	}

	if (! mddb_crctab)
		mddb_crctab = crcgentab();

	crctab = mddb_crctab;
	newcrc = MDDB_CRCMAGIC;

	recaddr = record;
	s = skip;
	while (size--) {
		/* Skip the result pointer */
		if (record == (uchar_t *)result) {
			record += sizeof (uint_t);
			size -= (sizeof (uint_t) - 1);
			continue;
		}

		/*
		 * Skip over next skip area if non-null
		 */
		if ((s) && (record == (recaddr + (s->skip_offset)))) {
			record += s->skip_size;
			size -= (s->skip_size - 1);
			s = s->skip_next;
			continue;
		}

		newcrc = (newcrc << 8) ^ crctab[(newcrc >> 24) ^ *record++];
	}

	/* If we are checking, we either get a 0 - OK, or 1 - Not OK result */
	if (check) {
		if (*((uint_t *)result) == newcrc)
			return (0);
		return (1);
	}

	/*
	 * If we are generating, we stuff the result, if we have a result
	 * pointer, and return the value.
	 */
	if (result != NULL)
		*((uint_t *)result) = newcrc;
	return (newcrc);
}

void
crcfreetab(void)
{
	if (mddb_crctab) {
		MD_FREE((caddr_t)mddb_crctab, 256 * sizeof (int));
		mddb_crctab = NULL;
	}
}
