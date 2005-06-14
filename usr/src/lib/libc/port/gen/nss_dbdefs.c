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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nss_dbdefs.h>
#include <limits.h>

/*
 * ALIGN? is there an official definition of this?
 * We use sizeof(long) to cover what we want
 * for both the 32-bit world and 64-bit world.
 */

#define	ALIGN(x) ((((long)(x)) + sizeof (long) - 1) & ~(sizeof (long) - 1))

nss_XbyY_buf_t *
_nss_XbyY_buf_alloc(int struct_size, int buffer_size)
{
	nss_XbyY_buf_t	*b;

	/* Use one malloc for dbargs, result struct and buffer */
	b = (nss_XbyY_buf_t *)
		malloc(ALIGN(sizeof (*b)) + struct_size + buffer_size);
	if (b == 0) {
		return (0);
	}
	b->result = (void *)ALIGN(&b[1]);
	b->buffer = (char *)(b->result) + struct_size;
	b->buflen = buffer_size;
	return (b);
}

void
_nss_XbyY_buf_free(nss_XbyY_buf_t *b)
{
	if (b != 0) {
		free(b);
	}
}

/* === Comment:  used by fget{gr,pw,sp}ent */
/* ==== Should do ye olde syslog()ing of suspiciously long lines */

void
_nss_XbyY_fgets(FILE *f, nss_XbyY_args_t *b)
{
	char		buf[LINE_MAX];
	int		len, parsestat;

	if (fgets(buf, LINE_MAX, f) == 0) {
		/* End of file */
		b->returnval = 0;
		b->erange    = 0;
		return;
	}
	len = (int)strlen(buf);
	/* len >= 0 (otherwise we would have got EOF) */
	if (buf[len - 1] != '\n') {
		if ((len + 1) == LINE_MAX) {
			/* Line too long for buffer; too bad */
			while (fgets(buf, LINE_MAX, f) != 0 &&
			    buf[strlen(buf) - 1] != '\n') {
				;
			}
			b->returnval = 0;
			b->erange    = 1;
			return;
		}
		/* case where the file is not terminated with a Newline */
		len++;
	}
	parsestat = (*b->str2ent)(buf, (len - 1), b->buf.result, b->buf.buffer,
		b->buf.buflen);
	if (parsestat == NSS_STR_PARSE_ERANGE) {
		b->returnval = 0;
		b->erange    = 1;
	} else if (parsestat == NSS_STR_PARSE_SUCCESS) {
		b->returnval = b->buf.result;
	}
}

/*
 * parse the aliases string into the buffer and if successful return
 * a char ** pointer to the beginning of the aliases.
 *
 * CAUTION: (instr, instr+lenstr) and (buffer, buffer+buflen) are
 * non-intersecting memory areas. Since this is an internal interface,
 * we should be able to live with that.
 */
char **
_nss_netdb_aliases(const char *instr, int lenstr, char *buffer, int buflen)
	/* "instr" is the beginning of the aliases string */
	/* "buffer" has the return val for success */
	/* "buflen" is the length of the buffer available for aliases */
{
	/*
	 * Build the alias-list in the start of the buffer, and copy
	 * the strings to the end of the buffer.
	 */
	const char
		*instr_limit	= instr + lenstr;
	char	*copyptr	= buffer + buflen;
	char	**aliasp	= (char **)ROUND_UP(buffer, sizeof (*aliasp));
	char	**alias_start	= aliasp;
	int	nstrings	= 0;

	for (;;) {
		const char	*str_start;
		size_t		str_len;

		while (instr < instr_limit && isspace(*instr)) {
			instr++;
		}
		if (instr >= instr_limit || *instr == '#') {
			break;
		}
		str_start = instr;
		while (instr < instr_limit && !isspace(*instr)) {
			instr++;
		}

		++nstrings;

		str_len = instr - str_start;
		copyptr -= str_len + 1;
		if (copyptr <= (char *)(&aliasp[nstrings + 1])) {
			/* Has to be room for the pointer to */
			/* the alias we're about to add,   */
			/* as well as the final NULL ptr.  */
			return (0);
		}
		*aliasp++ = copyptr;
		(void) memcpy(copyptr, str_start, str_len);
		copyptr[str_len] = '\0';
	}
	*aliasp++ = 0;
	return (alias_start);
}
