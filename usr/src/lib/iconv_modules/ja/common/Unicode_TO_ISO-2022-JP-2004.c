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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <errno.h>
#include <euc.h>

#include "japanese.h"
#include "jfp_iconv_unicode.h"

#define	JFP_U2E_ICONV_X0213
#include "jfp_ucs2_to_euc16.h"

#define	DEF_SINGLE	'?'

#define	CS0_SEQ2	0x28	/* ( */
#define	CS0_SEQ3	0x42	/* B */

#define	CS1_SEQ2	0x24	/* $ */
#define	CS1_SEQ3	0x28	/* ( */
#define	CS1_SEQ4	0x51	/* Q */

#define	CS3_SEQ2	0x24	/* $ */
#define	CS3_SEQ3	0x28	/* ( */
#define	CS3_SEQ4	0x50	/* P */

struct _icv_state {
	int	_st_cset;
};

void *
_icv_open(void)
{
	void			*cd;
	struct _icv_state	*st;

	cd = _icv_open_unicode(sizeof (struct _icv_state));

	if (cd != NULL) {
		st = (struct _icv_state *)(_icv_get_ext(cd));
		st->_st_cset = CS_0;
	}

	return (cd);
}

void
_icv_close(void *cd)
{
	_icv_close_unicode(cd);
	return;
}

size_t
_icv_iconv(void *cd, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	unsigned int	u32;		/* UTF-32 */
	unsigned short	e16;		/* 16-bit EUC */
	unsigned char	ic;
	size_t		rv = (size_t)0;

	struct _icv_state	*st = (struct _icv_state *)(_icv_get_ext(cd));
	int			cset;

	unsigned char	*ip;
        size_t		ileft;
	char		*op;
        size_t		oleft;

	/*
	 * If inbuf and/or *inbuf are NULL, reset conversion descriptor
	 * and put escape sequence if needed.
	 */
	if ((inbuf == NULL) || (*inbuf == NULL)) {
		if (st->_st_cset != CS_0) {
			if ((outbuf != NULL) && (*outbuf != NULL)
					&& (outbytesleft != NULL)) {
				op = (char *)*outbuf;
				oleft = *outbytesleft;
				NPUT(ESC, "RESET-SEQ-ESC");
				NPUT(CS0_SEQ2, "RESET-SEQ2");
				NPUT(CS0_SEQ3, "RESET-SEQ3");
				*outbuf = (char *)op;
				*outbytesleft = oleft;
			}
			st->_st_cset = CS_0;
			_icv_reset_unicode(cd);
		}
		return ((size_t)0);
	}

	cset = st->_st_cset;

	ip = (unsigned char *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		GETU(&u32)

		e16 = _jfp_u32_to_euc16(u32);

		switch (e16 & 0x8080) {
		case 0x0000:	/* CS0 */
			if (cset != CS_0) {
				NPUT(ESC, "CS0-SEQ-ESC");
				NPUT(CS0_SEQ2, "CS0-SEQ2");
				NPUT(CS0_SEQ3, "CS0-SEQ3");
				cset = CS_0;
			}
			ic = (unsigned char)e16;
			NPUT(ic, "CS0");
			break;
		case 0x8080:	/* CS1 */
			if (cset != CS_1) {
				NPUT(ESC, "CS1-SEQ-ESC");
				NPUT(CS1_SEQ2, "CS1-SEQ2");
				NPUT(CS1_SEQ3, "CS1-SEQ3");
				NPUT(CS1_SEQ4, "CS1-SEQ4");
				cset = CS_1;
			}
			ic = (unsigned char)((e16 >> 8) & 0x7f);
			NPUT(ic, "CS1-1");
			ic = (unsigned char)(e16 & 0x7f);
			NPUT(ic, "CS1-2");
			break;
		case 0x0080:	/* CS2 */
			if (cset != CS_0) {
				NPUT(ESC, "CS2-REPL-SEQ-ESC");
				NPUT(CS0_SEQ2, "CS2-REPL-SEQ2");
				NPUT(CS0_SEQ3, "CS2-REPL-SEQ3");
				cset = CS_0;
			}
			ic = DEF_SINGLE;
			NPUT(ic, "CS2-REPL");
			break;
		case 0x8000:	/* CS3 */
			if (cset != CS_3) {
				NPUT(ESC, "CS3-SEQ-ESC");
				NPUT(CS3_SEQ2, "CS3-SEQ2");
				NPUT(CS3_SEQ3, "CS3-SEQ3");
				NPUT(CS3_SEQ4, "CS3-SEQ4");
				cset = CS_3;
			}
			ic = (unsigned char)((e16 >> 8) & 0x7f);
			NPUT(ic, "CS3-1");
			ic = (unsigned char)(e16 & 0x7f);
			NPUT(ic, "CS3-2");
			break;
		}

next:
		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbuf = (char *)ip;
		*inbytesleft = ileft;
		*outbuf = op;
		*outbytesleft = oleft;

		st->_st_cset = cset;
	}

ret:

	DEBUGPRINTERROR

	/*
	 * Return value for successful return is not defined by XPG
	 * so return same as *inbytesleft as existing codes do.
	 */
	return ((rv == (size_t)-1) ? rv : *inbytesleft);
}
