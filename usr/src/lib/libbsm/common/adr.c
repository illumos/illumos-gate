/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Adr memory based encoding
 */

#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_record.h>

void
adr_start(adr_t *adr, char *p)
{
	adr->adr_stream = p;
	adr->adr_now = p;
}

int
adr_count(adr_t *adr)
{
	return (((intptr_t)adr->adr_now) - ((intptr_t)adr->adr_stream));
}


/*
 * adr_char - pull out characters
 */
void
adr_char(adr_t *adr, char *cp, int count)
{
	while (count-- > 0)
		*adr->adr_now++ = *cp++;
}

/*
 * adr_short - pull out shorts
 */
void
adr_short(adr_t *adr, short *sp, int count)
{

	for (; count-- > 0; sp++) {
		*adr->adr_now++ = (char)((*sp >> 8) & 0x00ff);
		*adr->adr_now++ = (char)(*sp & 0x00ff);
	}
}

/*
 * adr_ushort - pull out ushorts
 */
void
adr_ushort(adr_t *adr, ushort_t *sp, int count)
{

	for (; count-- > 0; sp++) {
		*adr->adr_now++ = (char)((*sp >> 8) & 0x00ff);
		*adr->adr_now++ = (char)(*sp & 0x00ff);
	}
}

/*
 * adr_int32 - pull out uint32
 */
#pragma weak adr_long = adr_int32
void
adr_long(adr_t *adr, int32_t *lp, int count);
void
adr_int32(adr_t *adr, int32_t *lp, int count)
{
	int i;		/* index for counting */
	uint32_t l;	/* value for shifting */

	for (; count-- > 0; lp++) {
		for (i = 0, l = *(uint32_t *)lp; i < 4; i++) {
			*adr->adr_now++ =
			    (char)((uint32_t)(l & 0xff000000) >> 24);
			l <<= 8;
		}
	}
}

/*
 * adr_uid
 */

void
adr_uid(adr_t *adr, uid_t *up, int count)
{
	int i;		/* index for counting */
	uid_t l;	/* value for shifting */

	for (; count-- > 0; up++) {
		for (i = 0, l = *(uint32_t *)up; i < 4; i++) {
			*adr->adr_now++ =
			    (char)((uint32_t)(l & 0xff000000) >> 24);
			l <<= 8;
		}
	}
}

/*
 * adr_int64 - pull out uint64_t
 */
void
adr_int64(adr_t *adr, int64_t *lp, int count)
{
	int i;		/* index for counting */
	uint64_t l;	/* value for shifting */

	for (; count-- > 0; lp++) {
		for (i = 0, l = *(uint64_t *)lp; i < 8; i++) {
			*adr->adr_now++ = (char)
			    ((uint64_t)(l & 0xff00000000000000ULL) >> 56);
			l <<= 8;
		}
	}
}
