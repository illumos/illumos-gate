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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/errno.h>
#include <sys/u8_textprep.h>
#include <sys/kiconv.h>
#include <sys/kiconv_cck_common.h>

/*LINTLIBRARY*/

/*
 * Common kiconv_open method for UTF-8 -> CCK conversion.
 */
void *
kiconv_open_to_cck()
{
	kiconv_state_t st;

	st = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);

	st->bom_processed = 0;

	return ((void *)st);
}

/*
 * Common kiconv_close method for UTF-8 -> CCK conversion.
 */
int
kiconv_close_to_cck(void *kcd)
{
	if (! kcd || kcd == (void *)-1)
		return (EBADF);

	kmem_free(kcd, sizeof (kiconv_state_data_t));

	return (0);
}

/*
 * Common routine to convert UTF-8 sequence to CCK legal character sequence.
 */
size_t
kiconv_utf8_to_cck(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno,
	kiconv_utf8tocck_t ptr_utf8tocck)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	size_t		i;		/* temp variable in for loop */
	uint32_t	u8;
	int8_t		sz;

	/* Check on the kiconv code conversion descriptor. */
	if (! kcd || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* If this is a state reset request, process and return. */
	if (! inbuf || !(*inbuf)) {
		((kiconv_state_t)kcd)->bom_processed = 0;
		return (0);
	}

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbytesleft;
	obtail = ob + *outbytesleft;

	KICONV_CHECK_UTF8_BOM(ib, ibtail);

	while (ib < ibtail) {
		sz = u8_number_of_bytes[*ib];

		/*
		 * If it is a 7-bit ASCII character, we don't need to
		 * process further and we just copy the character over.
		 *
		 * If not, we connect the chracter bytes up to four bytes,
		 * validate the bytes, and binary search for the corresponding
		 * table. If we find it from the mapping table, we put that
		 * into the output buffer; otherwise, we put a replacement
		 * character instead as a non-identical conversion.
		 */
		if (sz == 1) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		/*
		 * Issue EILSEQ error if the first byte is a
		 * invalid UTF-8 character leading byte.
		 */
		if (sz <= 0) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/*
		 * Issue EINVAL error if input buffer has an incomplete
		 * character at the end of the buffer.
		 */
		if (ibtail - ib < sz) {
			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		/*
		 * We collect UTF-8 character bytes and also check if this
		 * is a valid UTF-8 character without any bogus bytes based
		 * on the latest UTF-8 binary representation.
		 */
		oldib = ib;
		u8 = *ib++;

		if (KICONV_IS_INVALID_UTF8_SECOND_BYTE(*ib, u8))
			goto ILLEGAL_CHAR_PROCESS;
		u8 = (u8 << 8) | *ib++;

		for (i = 2; i < sz; i++) {
			if (*ib < 0x80 || *ib > 0xbf) {
ILLEGAL_CHAR_PROCESS:
				*errno = EILSEQ;
				ret_val = (size_t)-1;
				ib = oldib;
				goto ILLEGAL_CHAR_ERR;
			}

			u8 = (u8 << 8) | *ib++;
		}

		/* Now we have a valid UTF-8 character. */
		sz = ptr_utf8tocck(u8, &ib, ibtail, ob, obtail, &ret_val);
		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
	}

ILLEGAL_CHAR_ERR:
	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

size_t
kiconvstr_utf8_to_cck(uchar_t *ib, size_t *inlen, uchar_t *ob, size_t *outlen,
	int flag, int *errno, kiconv_utf8tocck_t ptr_utf8tocck)
{
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	size_t		i;		/* temp variable in for loop */
	uint32_t	u8;
	int8_t		sz;
	boolean_t	do_not_ignore_null;

	ret_val = 0;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	KICONV_CHECK_UTF8_BOM_WITHOUT_STATE(ib, ibtail);

	while (ib < ibtail) {
		if (*ib == '\0' && do_not_ignore_null)
			break;

		sz = u8_number_of_bytes[*ib];

		if (sz == 1) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		oldib = ib;

		if (sz <= 0) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		if (ibtail - ib < sz) {
			if (flag & KICONV_REPLACE_INVALID) {
				ib = ibtail;
				goto REPLACE_INVALID;
			}

			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		u8 = *ib++;

		if (KICONV_IS_INVALID_UTF8_SECOND_BYTE(*ib, u8))
			goto ILLEGAL_CHAR_PROCESS;
		u8 = (u8 << 8) | *ib++;

		for (i = 2; i < sz; i++) {
			if (*ib < 0x80 || *ib > 0xbf) {
ILLEGAL_CHAR_PROCESS:
				if (flag & KICONV_REPLACE_INVALID) {
					ib = oldib + sz;
					goto REPLACE_INVALID;
				}

				*errno = EILSEQ;
				ret_val = (size_t)-1;
				ib = oldib;
				goto ILLEGAL_CHAR_ERR;
			}

			u8 = (u8 << 8) | *ib++;
		}

		/* Now we get a valid character encoded in UTF-8. */
		sz = ptr_utf8tocck(u8, &ib, ibtail, ob, obtail, &ret_val);
		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
		continue;

REPLACE_INVALID:
		if (ob >= obtail) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		*ob++ = KICONV_ASCII_REPLACEMENT_CHAR;
		ret_val++;
	}

ILLEGAL_CHAR_ERR:
	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * Search key in tbl[0] <= tbl[1] <= ... <= tbl[n-1].  Return 0 if not found.
 * tbl[0] is a special element for non-identical conversion.
 */
size_t
kiconv_binsearch(uint32_t key, void *tbl, size_t nitems)
{
	size_t low, high, mid;
	kiconv_table_t *table;

	low = 1;
	high = nitems - 1;
	table = (kiconv_table_t *)tbl;

	while (low <= high) {
		mid = (low + high) / 2;

		if (key < table[mid].key)
			high = mid - 1;
		else if (key > table[mid].key)
			low = mid + 1;
		else
			return (mid);
	}

	return (0);
}
