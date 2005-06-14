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

/*
 * Adr memory based encoding
 */

#include <sys/feature_tests.h>

#pragma weak adr_ushort = adr_short
#pragma weak adr_uint32 = adr_int32
#pragma weak adr_uint64 = adr_int64
#pragma weak adr_getushort = adr_getshort
#pragma weak adr_getuint32 = adr_getint32
#pragma weak adr_getuint64 = adr_getint64

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/thread.h>
#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>

void
adr_start(adr_t *adr, char *p)
{
	adr->adr_stream = p;
	adr->adr_now = p;
}

int
adr_count(adr_t *adr)
{
	return ((int)((uintptr_t)adr->adr_now - (uintptr_t)adr->adr_stream));
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
		*adr->adr_now++ = (char)((*sp >> (int)8) & 0x00ff);
		*adr->adr_now++ = (char)(*sp & 0x00ff);
	}
}

/*
 * adr_int32 - pull out int32
 */
void
adr_int32(adr_t *adr, int32_t *lp, int count)
{
	int i;		/* index for counting */
	int32_t l;		/* value for shifting */

	for (; count-- > 0; lp++) {
		for (i = 0, l = *lp; i < 4; i++) {
			*adr->adr_now++ = (char)((l & (int32_t)0xff000000) >>
				(int)24);
			l <<= (int)8;
		}
	}
}

/*
 * adr_int64 - pull out int64
 */
void
adr_int64(adr_t *adr, int64_t *lp, int count)
{
	int i;		/* index for counting */
	int64_t l;	/* value for shifting */

	for (; count-- > 0; lp++) {
		for (i = 0, l = *lp; i < 8; i++) {
		    *adr->adr_now++ =
			(char)((l & (int64_t)0xff00000000000000) >> (int)56);
			l <<= (int)8;
		}
	}
}


char *
adr_getchar(adr_t *adr, char *cp)
{
	char	*old;

	old = adr->adr_now;
	*cp = *adr->adr_now++;
	return (old);
}

char *
adr_getshort(adr_t *adr, short	*sp)
{
	char	*old;

	old = adr->adr_now;
	*sp = *adr->adr_now++;
	*sp >>= (int)8;
	*sp = *adr->adr_now++;
	*sp >>= (int)8;
	return (old);
}

char *
adr_getint32(adr_t *adr, int32_t *lp)
{
	char	*old;
	int	i;

	old = adr->adr_now;
	for (i = 0; i < 4; i++) {
		*lp <<= 8;
		*lp += ((int32_t)*adr->adr_now++) & 0x000000ff;

	}
	return (old);
}

char *
adr_getint64(adr_t *adr, int64_t *lp)
{
	char	*old;
	int	i;

	old = adr->adr_now;
	for (i = 0; i < 8; i++) {
		*lp <<= 8;
		*lp += ((int64_t)*adr->adr_now++) & 0x00000000000000ff;
	}
	return (old);
}
