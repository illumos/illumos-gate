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

#include <stdio.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_record.h>


/*
 * adr_struct.now is used to calculate the record length so
 * end of record will be recognized.
 */


void
adrf_start(adrf_t *adrf, adr_t *adr, FILE *fp)
{
	adrf->adrf_fp = fp;
	adrf->adrf_adr = adr;
	adrf->adrf_adr->adr_now = NULL;
}

/*
 * adrf_char - pull out characters
 */
int
adrf_char(adrf_t *adrf, char *cp, int count)
{
	int c;	/* read character in here */

	if (count < 0)
		return (-1);
	while (count--) {
		if ((c = fgetc(adrf->adrf_fp)) == EOF)
			return (-1);
		*cp++ = c;
		adrf->adrf_adr->adr_now += sizeof (char);
	}
	return (0);
}

/*
 * adrf_short - pull out shorts
 */
int
adrf_short(adrf_t *adrf, short *sp, int count)
{
	int c;	/* read character in here */

	if (count < 0)
		return (-1);
	while (count--) {
		if ((c = fgetc(adrf->adrf_fp)) == EOF)
			return (-1);
		*sp = c << 8;
		if ((c = fgetc(adrf->adrf_fp)) == EOF)
			return (-1);
		*sp++ |= c & 0x00ff;
		adrf->adrf_adr->adr_now += sizeof (short);
	}
	return (0);
}

/*
 * adrf_int32 - pull out int32
 */
int adrf_int(adrf_t *adrf, int32_t *lp, int count);
int adrf_long(adrf_t *adrf, int32_t *lp, int count);

#pragma weak adrf_int = adrf_int32
#pragma weak adrf_long = adrf_int32

int
adrf_int32(adrf_t *adrf, int32_t *lp, int count)
{
	int i;
	int c;	/* read character in here */

	if (count < 0)
		return (-1);
	for (; count--; lp++) {
		*lp = 0;
		for (i = 0; i < 4; i++) {
			if ((c = fgetc(adrf->adrf_fp)) == EOF)
				return (-1);
			*lp <<= 8;
			*lp |= c & 0x000000ff;
		}
		adrf->adrf_adr->adr_now += sizeof (int32_t);
	}
	return (0);
}

int
adrf_int64(adrf_t *adrf, int64_t *lp, int count)
{
	int i;
	int c;	/* read character in here */

	if (count < 0)
		return (-1);
	for (; count--; lp++) {
		*lp = 0;
		for (i = 0; i < 8; i++) {
			if ((c = fgetc(adrf->adrf_fp)) == EOF)
				return (-1);
			*lp <<= 8;
			*lp |= c & 0x00000000000000ff;
		}
		adrf->adrf_adr->adr_now += sizeof (int64_t);
	}
	return (0);
}

int adrf_u_int(adrf_t *adrf, uint32_t *cp, int count);
int adrf_u_long(adrf_t *adrf, uint32_t *cp, int count);

#pragma weak adrf_u_int = adrf_u_int32
#pragma weak adrf_u_long = adrf_u_int32

int
adrf_u_int32(adrf_t *adrf, uint32_t *cp, int count)
{
	return (adrf_int32(adrf, (int32_t *)cp, count));
}

int
adrf_u_char(adrf_t *adrf, uchar_t *cp, int count)
{
	return (adrf_char(adrf, (char *)cp, count));
}

int
adrf_u_int64(adrf_t *adrf, uint64_t *lp, int count)
{
	return (adrf_int64(adrf, (int64_t *)lp, count));
}

int
adrf_u_short(adrf_t *adrf, ushort_t *sp, int count)
{
	return (adrf_short(adrf, (short *)sp, count));
}

int
adrf_peek(adrf_t *adrf)
{
	return (ungetc(fgetc(adrf->adrf_fp), adrf->adrf_fp));
}
