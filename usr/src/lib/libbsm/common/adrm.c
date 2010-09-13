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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Adr memory based translations
 */

#include <stdio.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>

void
adrm_start(adr_t *adr, char *p)
{
	adr->adr_stream = p;
	adr->adr_now = p;
}

/*
 * adrm_char - pull out characters
 */
void
adrm_char(adr_t *adr, char *cp, int count)
{
	while (count-- > 0)
		*cp++ = *adr->adr_now++;
}

/*
 * adrm_short - pull out shorts
 */
void
adrm_short(adr_t *adr, short *sp, int count)
{
	while (count-- > 0) {
		*sp = *adr->adr_now++ << 8;
		*sp++ += ((short)*adr->adr_now++) & 0x00ff;
	}
}

/*
 * adrm_int32 - pull out int
 */
void adrm_int(adr_t *adr, int32_t *lp, int count);
void adrm_long(adr_t *adr, int32_t *lp, int count);
#pragma weak adrm_int = adrm_int32
#pragma weak adrm_long = adrm_int32

void
adrm_int32(adr_t *adr, int32_t *lp, int count)
{
	int i;

	for (; count-- > 0; lp++) {
		*lp = 0;
		for (i = 0; i < 4; i++) {
			*lp <<= 8;
			*lp += ((int32_t)*adr->adr_now++) & 0x000000ff;
		}
	}
}

void
adrm_uid(adr_t *adr, uid_t *up, int count)
{
	int i;

	for (; count-- > 0; up++) {
		*up = 0;
		for (i = 0; i < 4; i++) {
			*up <<= 8;
			*up += ((uid_t)*adr->adr_now++) & 0x000000ff;
		}
	}
}

void
adrm_int64(adr_t *adr, int64_t *lp, int count)
{
	int i;

	for (; count-- > 0; lp++) {
		*lp = 0;
		for (i = 0; i < 8; i++) {
			*lp <<= 8;
			*lp += ((int64_t)*adr->adr_now++) & 0x00000000000000ff;
		}
	}
}

void adrm_u_int(adr_t *adr, uint32_t *cp, int count);
void adrm_u_long(adr_t *adr, uint32_t *cp, int count);
#pragma weak adrm_u_int = adrm_u_int32
#pragma weak adrm_u_long = adrm_u_int32

void
adrm_u_int32(adr_t *adr, uint32_t *cp, int count)
{
	adrm_int32(adr, (int32_t *)cp, count);
}

void
adrm_u_char(adr_t *adr, uchar_t *cp, int count)
{
	adrm_char(adr, (char *)cp, count);
}

void
adrm_u_int64(adr_t *adr, uint64_t *lp, int count)
{
	adrm_int64(adr, (int64_t *)lp, count);
}

void
adrm_u_short(adr_t *adr, ushort_t *sp, int count)
{
	adrm_short(adr, (short *)sp, count);
}

/*
 * adrm_putint32 - pack in int32
 */
#pragma weak adrm_putint = adrm_putint32
#pragma weak adrm_putlong = adrm_putint32
void
adrm_putint32(adr_t *adr, int32_t *lp, int count)
{
	int i;		/* index for counting */
	int32_t l;	/* value for shifting */

	for (; count-- > 0; lp++) {
		for (i = 0, l = *lp; i < 4; i++) {
			*adr->adr_now++ = (char)((l & (int32_t)0xff000000) >>
			    (int)24);
			l <<= (int)8;
		}
	}
}
