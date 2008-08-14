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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>
#include <stdio.h>
#include <sys/varargs.h>
#include <mms_trace.h>

void
int32_to_char(int32_t val, uchar_t *start, int len)
{
	int i;
	int shift;

	for (i = 0, shift = (len - 1) * 8; i < len; i++, shift -= 8) {
		start[i] = (val >> shift);
	}
}

void
int64_to_char(int64_t val, uchar_t *start, int len)
{
	int i;
	int shift;

	for (i = 0, shift = (len - 1) * 8; i < len; i++, shift -= 8) {
		start[i] = (val >> shift);
	}
}

void
char_to_int32(signed char *start, int len, int32_t *val)
{
	int i;
	/* LINTED: to satisfy lint */
	int	shift;

	*val = start[0];
	for (i = 1, shift = (len - 1) * 8; i < len; i++) {
		*val = (*val << 8) | (start[i] & 0xff);
	}
}

void
char_to_uint32(uchar_t *start, int len, uint32_t *val)
{
	int i;
	/* LINTED: to satisfy lint */
	int	shift;

	*val = 0;
	for (i = 0, shift = (len - 1) * 8; i < len; i++) {
		*val = (*val << 8) | (start[i] & 0xff);
	}
}

void
char_to_int64(signed char *start, int len, int64_t *val)
{
	int i;
	/* LINTED: to satisfy lint */
	int	shift;

	*val = start[0];
	for (i = 1, shift = (len - 1) * 8; i < len; i++) {
		*val = (*val << 8) | (start[i] & 0xff);
	}
}

void
char_to_uint64(uchar_t *start, int len, uint64_t *val)
{
	int i;
	/* LINTED: to satisfy lint */
	int	shift;

	*val = 0;
	for (i = 0, shift = (len - 1) * 8; i < len; i++) {
		*val = (*val << 8) | (start[i] & 0xff);
	}
}

void
dm_trim_tail(char *str)
{
	int len;
	int i;

	len = strlen(str);

	for (i = len - 1; i >= 0; i--) {
		if (str[i] == ' ') {
			str[i] = '\0';
		} else {
			return;
		}
	}
}

void
dm_to_upper(char *vp)
{
	int i;

	for (i = 0; vp[i] != '\0'; i++) {
		vp[i] = toupper(vp[i]);
	}
}

char *
dm_char_to_hex(uchar_t *ibuf, int ilen, char *obuf, int olen)
{
	int	ioff;
	int	ooff;
	int	olmt = olen - 1;
	int	i;

	for (ioff = 0, ooff = 0; ioff < ilen; ) {
		for (i = 0; (i < 4) && (ioff < ilen); i++) {
			if (ooff > (olmt - 2)) {
				/* Need 2 output chars for a sense byte */
				break;
			}
			snprintf(obuf + ooff, olmt - ooff, "%2.2x", ibuf[ioff]);
			ioff++;
			ooff += 2;
		}
		if (ooff > (olmt - 3)) {
			/* Need 3 output chars for a blank and a sense byte */
			break;
		}
		obuf[ooff] = ' ';
		ooff++;
	}
	obuf[ooff] = '\0';
	return (obuf);
}
