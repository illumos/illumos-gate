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
 * Kernel iconv code conversion module (kiconv_emea) for Europe, Middle East,
 * and South East Asia (PSARC/2007/173).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/byteorder.h>
#include <sys/errno.h>
#include <sys/kiconv.h>
#include <sys/kiconv_emea1.h>
#include <sys/kiconv_emea2.h>


/*
 * The following macros indicate ids to the correct code conversion mapping
 * data tables to use. The actual tables are coming from <sys/kiconv_emea1.h>
 * and <sys/kiconv_emea2.h>. If you update the header files, then, you might
 * also need to update the table ids at below.
 *
 * The table for KICONV_TBLID_720 is a special case and should come from
 * a separate header file than others at <sys/kiconv_emea1.h> hence it has
 * an id that is rather unusual distinguishing itself from others. (And,
 * the ids much be of uint8_t.)
 */
#define	KICONV_TBLID_720		(0xFFU)
#define	KICONV_TBLID_RANGE1_START	KICONV_TBLID_720
#define	KICONV_TBLID_RANGE1_END		KICONV_TBLID_720

#define	KICONV_TBLID_737		(0)
#define	KICONV_TBLID_852		(1)
#define	KICONV_TBLID_857		(2)
#define	KICONV_TBLID_862		(3)
#define	KICONV_TBLID_866		(4)
#define	KICONV_TBLID_1250		(5)
#define	KICONV_TBLID_1251		(6)
#define	KICONV_TBLID_1253		(7)
#define	KICONV_TBLID_1254		(8)
#define	KICONV_TBLID_1255		(9)
#define	KICONV_TBLID_1256		(10)
#define	KICONV_TBLID_1257		(11)
#define	KICONV_TBLID_8859_2		(12)
#define	KICONV_TBLID_8859_3		(13)
#define	KICONV_TBLID_8859_4		(14)
#define	KICONV_TBLID_8859_5		(15)
#define	KICONV_TBLID_8859_6		(16)
#define	KICONV_TBLID_8859_7		(17)
#define	KICONV_TBLID_8859_8		(18)
#define	KICONV_TBLID_8859_9		(19)
#define	KICONV_TBLID_8859_10		(20)
#define	KICONV_TBLID_8859_11		(21)
#define	KICONV_TBLID_8859_13		(22)
#define	KICONV_TBLID_KOI8_R		(23)

#define	KICONV_MAX_MAPPING_TBLID	KICONV_TBLID_KOI8_R

/*
 * The following tables are coming from u8_textprep.c. We use them to
 * check on validity of UTF-8 characters and their bytes.
 */
extern const int8_t u8_number_of_bytes[];
extern const uint8_t u8_valid_min_2nd_byte[];
extern const uint8_t u8_valid_max_2nd_byte[];


/*
 * The following 25 open_to_xxxx() functions are kiconv_open functions for
 * the conversions from UTF-8 to xxxx single byte codesets.
 */
static void *
open_to_720()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_720;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_737()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_737;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_852()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_852;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_857()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_857;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_862()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_862;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_866()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_866;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1250()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1250;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1251()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1251;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1253()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1253;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1254()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1254;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1255()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1255;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1256()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1256;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_1257()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1257;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88592()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_2;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88593()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_3;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88594()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_4;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88595()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_5;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88596()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_6;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88597()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_7;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88598()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_8;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88599()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_9;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_885910()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_10;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_885911()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_11;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_885913()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_13;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_koi8r()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_KOI8_R;
	s->bom_processed = 0;

	return ((void *)s);
}

/*
 * The following 25 open_fr_xxxx() functions are kiconv_open functions for
 * the conversions from xxxx single byte codeset to UTF-8.
 */
static void *
open_fr_720()
{
	return ((void *)KICONV_TBLID_720);
}

static void *
open_fr_737()
{
	return ((void *)KICONV_TBLID_737);
}

static void *
open_fr_852()
{
	return ((void *)KICONV_TBLID_852);
}

static void *
open_fr_857()
{
	return ((void *)KICONV_TBLID_857);
}

static void *
open_fr_862()
{
	return ((void *)KICONV_TBLID_862);
}

static void *
open_fr_866()
{
	return ((void *)KICONV_TBLID_866);
}

static void *
open_fr_1250()
{
	return ((void *)KICONV_TBLID_1250);
}

static void *
open_fr_1251()
{
	return ((void *)KICONV_TBLID_1251);
}

static void *
open_fr_1253()
{
	return ((void *)KICONV_TBLID_1253);
}

static void *
open_fr_1254()
{
	return ((void *)KICONV_TBLID_1254);
}

static void *
open_fr_1255()
{
	return ((void *)KICONV_TBLID_1255);
}

static void *
open_fr_1256()
{
	return ((void *)KICONV_TBLID_1256);
}

static void *
open_fr_1257()
{
	return ((void *)KICONV_TBLID_1257);
}

static void *
open_fr_88592()
{
	return ((void *)KICONV_TBLID_8859_2);
}

static void *
open_fr_88593()
{
	return ((void *)KICONV_TBLID_8859_3);
}

static void *
open_fr_88594()
{
	return ((void *)KICONV_TBLID_8859_4);
}

static void *
open_fr_88595()
{
	return ((void *)KICONV_TBLID_8859_5);
}

static void *
open_fr_88596()
{
	return ((void *)KICONV_TBLID_8859_6);
}

static void *
open_fr_88597()
{
	return ((void *)KICONV_TBLID_8859_7);
}

static void *
open_fr_88598()
{
	return ((void *)KICONV_TBLID_8859_8);
}

static void *
open_fr_88599()
{
	return ((void *)KICONV_TBLID_8859_9);
}

static void *
open_fr_885910()
{
	return ((void *)KICONV_TBLID_8859_10);
}

static void *
open_fr_885911()
{
	return ((void *)KICONV_TBLID_8859_11);
}

static void *
open_fr_885913()
{
	return ((void *)KICONV_TBLID_8859_13);
}

static void *
open_fr_koi8r()
{
	return ((void *)KICONV_TBLID_KOI8_R);
}

/*
 * The following is the common kiconv_close function for the conversions from
 * UTF-8 to single byte codesets.
 */
static int
close_to_sb(void *s)
{
	if (! s || s == (void *)-1)
		return (EBADF);

	kmem_free(s, sizeof (kiconv_state_data_t));

	return (0);
}

/*
 * The following is the common kiconv_close function for the conversions from
 * single byte codesets to UTF-8.
 */
static int
close_fr_sb(void *s)
{
	if ((ulong_t)s > KICONV_MAX_MAPPING_TBLID &&
	    ((ulong_t)s < KICONV_TBLID_RANGE1_START ||
	    (ulong_t)s > KICONV_TBLID_RANGE1_END))
		return (EBADF);

	return (0);
}

/*
 * The following is the common kiconv function for the conversions from
 * UTF-8 to single byte codesets. (This may look a lot similar to
 * kiconvstr_to_sb() but they do have different features to cover and
 * it's not really worth to try to merge them into a single function since
 * you'll have to add performance penalty for both per each character
 * conversion as you will have to figure out if this is kiconv_to_sb() or
 * kiconvstr_to_sb().)
 */
static size_t
kiconv_to_sb(void *kcd, char **inbuf, size_t *inbytesleft, char **outbuf,
	size_t *outbytesleft, int *errno)
{
	kiconv_to_sb_tbl_comp_t *tbl;
	size_t id;
	size_t ret_val;
	uchar_t *ib;
	uchar_t *oldib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;
	uint32_t u8;
	size_t i;
	size_t l;
	size_t h;
	size_t init_h;
	int8_t sz;
	boolean_t second;

	/* Check on the kiconv code conversion descriptor. */
	if (! kcd || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* Get the table id and check on it. */
	id = ((kiconv_state_t)kcd)->id;
	if (id > KICONV_MAX_MAPPING_TBLID &&
	    (id < KICONV_TBLID_RANGE1_START || id > KICONV_TBLID_RANGE1_END)) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* If this is a state reset request, process and return. */
	if (! inbuf || ! (*inbuf)) {
		((kiconv_state_t)kcd)->bom_processed = 0;
		return ((size_t)0);
	}

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbytesleft;
	obtail = ob + *outbytesleft;

	/*
	 * Get the table we want to use and also calculate the "init_h"
	 * which is the initial high index for the binary search that we will
	 * use. While the table sizes are all the same at the moment, to be
	 * ready for future cases where tables could be in different sizes,
	 * we separately calculate the init_h at here.
	 */
	if (id == KICONV_TBLID_720) {
		tbl = (kiconv_to_sb_tbl_comp_t *)u8_to_cp720_tbl;
		init_h = sizeof (u8_to_cp720_tbl);
	} else {
		tbl = (kiconv_to_sb_tbl_comp_t *)to_sb_tbl[id];
		init_h = sizeof (to_sb_tbl[id]);
	}
	init_h = init_h / sizeof (kiconv_to_sb_tbl_comp_t) - 1;

	/*
	 * If we haven't checked on the UTF-8 signature BOM character in
	 * the beginning of the conversion data stream, we check it and if
	 * find one, we skip it since we have no use for it.
	 */
	if (((kiconv_state_t)kcd)->bom_processed == 0 && (ibtail - ib) >= 3 &&
	    *ib == 0xef && *(ib + 1) == 0xbb && *(ib + 2) == 0xbf)
			ib += 3;
	((kiconv_state_t)kcd)->bom_processed = 1;

	while (ib < ibtail) {
		sz = u8_number_of_bytes[*ib];
		if (sz <= 0) {
			*errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		/*
		 * If there is no room to write at the output buffer,
		 * we issue E2BIG and let the caller knows about it.
		 */
		if (ob >= obtail) {
			*errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		/*
		 * If it is a 7-bit ASCII character, we don't need to
		 * process further and we just copy the character over.
		 *
		 * If not, we collect the character bytes up to four bytes,
		 * validate the bytes, and binary search for the corresponding
		 * single byte codeset character byte. If we find it from
		 * the mapping table, we put that into the output buffer;
		 * otherwise, we put a replacement character instead as
		 * a non-identical conversion.
		 */
		if (sz == 1) {
			*ob++ = *ib++;
			continue;
		}

		/*
		 * Issue EINVAL if the last character at the input buffer
		 * is an incomplete character missing a byte or more.
		 */
		if ((ibtail - ib) < sz) {
			*errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		/*
		 * We collect UTF-8 character bytes and at the same time,
		 * check on if the bytes are valid bytes or not. This follows
		 * the latest UTF-8 byte representation.
		 */
		oldib = ib;
		u8 = *ib++;
		second = B_TRUE;
		for (i = 1; i < sz; i++) {
			if (second) {
				if (*ib < u8_valid_min_2nd_byte[u8] ||
				    *ib > u8_valid_max_2nd_byte[u8]) {
					*errno = EILSEQ;
					ret_val = (size_t)-1;
					ib = oldib;
					goto TO_SB_ILLEGAL_CHAR_ERR;
				}
				second = B_FALSE;
			} else if (*ib < 0x80 || *ib > 0xbf) {
				*errno = EILSEQ;
				ret_val = (size_t)-1;
				ib = oldib;
				goto TO_SB_ILLEGAL_CHAR_ERR;
			}
			u8 = (u8 << 8) | ((uint32_t)*ib);
			ib++;
		}

		i = l = 0;
		h = init_h;
		while (l <= h) {
			i = (l + h) / 2;
			if (tbl[i].u8 == u8)
				break;
			else if (tbl[i].u8 < u8)
				l = i + 1;
			else
				h = i - 1;
		}

		if (tbl[i].u8 == u8) {
			*ob++ = tbl[i].sb;
		} else {
			/*
			 * What this means is that we encountered
			 * a non-identical conversion. In other words,
			 * input buffer contains a valid character in
			 * the fromcode but the tocode doesn't have
			 * any character that can be mapped to.
			 *
			 * In this case, we insert an ASCII replacement
			 * character instead at the output buffer and
			 * count such non-identical conversions by
			 * increasing the ret_val.
			 *
			 * If the return value of the function is bigger
			 * than zero, that means we had such non-identical
			 * conversion(s).
			 */
			*ob++ = KICONV_ASCII_REPLACEMENT_CHAR;
			ret_val++;
		}
	}

TO_SB_ILLEGAL_CHAR_ERR:
	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

/*
 * The following is the common kiconv function for the conversions from
 * single byte codesets to UTf-8.
 */
static size_t
kiconv_fr_sb(void *kcd, char **inbuf, size_t *inbytesleft, char **outbuf,
	size_t *outbytesleft, int *errno)
{
	kiconv_to_utf8_tbl_comp_t *tbl;
	size_t ret_val;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;
	size_t i;
	size_t k;
	int8_t sz;

	/* Validate the kiconv code conversion descriptor. */
	if ((ulong_t)kcd > KICONV_MAX_MAPPING_TBLID &&
	    ((ulong_t)kcd < KICONV_TBLID_RANGE1_START ||
	    (ulong_t)kcd > KICONV_TBLID_RANGE1_END)) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/*
	 * If this is a state reset request, there is nothing to do and so
	 * we just return.
	 */
	if (! inbuf || ! (*inbuf))
		return ((size_t)0);

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbytesleft;
	obtail = ob + *outbytesleft;

	tbl = ((ulong_t)kcd == KICONV_TBLID_720) ?
	    (kiconv_to_utf8_tbl_comp_t *)cp720_to_u8_tbl :
	    (kiconv_to_utf8_tbl_comp_t *)to_u8_tbl[(ulong_t)kcd];

	while (ib < ibtail) {
		/*
		 * If this is a 7-bit ASCII character, we just copy over and
		 * that's all we need to do for this character.
		 */
		if (*ib < 0x80) {
			if (ob >= obtail) {
				*errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}

			*ob++ = *ib++;
			continue;
		}

		/*
		 * Otherwise, we get the corresponding UTF-8 character bytes
		 * from the mapping table and copy them over.
		 *
		 * We don't need to worry about if the UTF-8 character bytes
		 * at the mapping tables are valid or not since they are good.
		 */
		k = *ib - 0x80;
		sz = u8_number_of_bytes[tbl[k].u8[0]];

		/*
		 * If (sz <= 0), that means the character in the input buffer
		 * is an illegal character possibly unassigned or non-character
		 * at the fromcode single byte codeset.
		 */
		if (sz <= 0) {
			*errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((obtail - ob) < sz) {
			*errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		for (i = 0; i < sz; i++)
			*ob++ = tbl[k].u8[i];

		ib++;
	}

	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

/*
 * The following is the common kiconvstr function for the conversions from
 * UTF-8 to single byte codeset.
 */
static size_t
kiconvstr_to_sb(size_t id, uchar_t *ib, size_t *inlen, uchar_t *ob,
	size_t *outlen, int flag, int *errno)
{
	kiconv_to_sb_tbl_comp_t *tbl;
	size_t ret_val;
	uchar_t *oldib;
	uchar_t *ibtail;
	uchar_t *obtail;
	uint32_t u8;
	size_t i;
	size_t l;
	size_t h;
	size_t init_h;
	int8_t sz;
	boolean_t second;
	boolean_t do_not_ignore_null;

	/* Let's double check on the table id. */
	if (id > KICONV_MAX_MAPPING_TBLID &&
	    (id < KICONV_TBLID_RANGE1_START || id > KICONV_TBLID_RANGE1_END)) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	ret_val = 0;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	if (id == KICONV_TBLID_720) {
		tbl = (kiconv_to_sb_tbl_comp_t *)u8_to_cp720_tbl;
		init_h = sizeof (u8_to_cp720_tbl);
	} else {
		tbl = (kiconv_to_sb_tbl_comp_t *)to_sb_tbl[id];
		init_h = sizeof (to_sb_tbl[id]);
	}
	init_h = init_h / sizeof (kiconv_to_sb_tbl_comp_t) - 1;

	/* Skip any UTF-8 signature BOM character in the beginning. */
	if ((ibtail - ib) >= 3 && *ib == 0xef && *(ib + 1) == 0xbb &&
	    *(ib + 2) == 0xbf)
			ib += 3;

	/*
	 * Basically this is pretty much the same as kiconv_to_sb() except
	 * that we are now accepting two flag values and doing the processing
	 * accordingly.
	 */
	while (ib < ibtail) {
		sz = u8_number_of_bytes[*ib];
		if (sz <= 0) {
			if (flag & KICONV_REPLACE_INVALID) {
				if (ob >= obtail) {
					*errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}

				ib++;
				goto STR_TO_SB_REPLACE_INVALID;
			}

			*errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if (*ib == '\0' && do_not_ignore_null)
			break;

		if (ob >= obtail) {
			*errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		if (sz == 1) {
			*ob++ = *ib++;
			continue;
		}

		if ((ibtail - ib) < sz) {
			if (flag & KICONV_REPLACE_INVALID) {
				ib = ibtail;
				goto STR_TO_SB_REPLACE_INVALID;
			}

			*errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		oldib = ib;
		u8 = *ib++;
		second = B_TRUE;
		for (i = 1; i < sz; i++) {
			if (second) {
				if (*ib < u8_valid_min_2nd_byte[u8] ||
				    *ib > u8_valid_max_2nd_byte[u8]) {
					if (flag & KICONV_REPLACE_INVALID) {
						ib = oldib + sz;
						goto STR_TO_SB_REPLACE_INVALID;
					}

					*errno = EILSEQ;
					ret_val = (size_t)-1;
					ib = oldib;
					goto STR_TO_SB_ILLEGAL_CHAR_ERR;
				}
				second = B_FALSE;
			} else if (*ib < 0x80 || *ib > 0xbf) {
				if (flag & KICONV_REPLACE_INVALID) {
					ib = oldib + sz;
					goto STR_TO_SB_REPLACE_INVALID;
				}

				*errno = EILSEQ;
				ret_val = (size_t)-1;
				ib = oldib;
				goto STR_TO_SB_ILLEGAL_CHAR_ERR;
			}
			u8 = (u8 << 8) | ((uint32_t)*ib);
			ib++;
		}

		i = l = 0;
		h = init_h;
		while (l <= h) {
			i = (l + h) / 2;
			if (tbl[i].u8 == u8)
				break;
			else if (tbl[i].u8 < u8)
				l = i + 1;
			else
				h = i - 1;
		}

		if (tbl[i].u8 == u8) {
			*ob++ = tbl[i].sb;
		} else {
STR_TO_SB_REPLACE_INVALID:
			*ob++ = KICONV_ASCII_REPLACEMENT_CHAR;
			ret_val++;
		}
	}

STR_TO_SB_ILLEGAL_CHAR_ERR:
	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * The following 25 functions are the real entry points that will be
 * given to the kiconv framework at the genunix.
 */
static size_t
kiconvstr_to_720(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_720, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_737(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_737, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_852(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_852, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_857(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_857, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_862(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_862, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_866(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_866, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1250(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1250, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1251(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1251, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1253(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1253, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1254(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1254, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1255(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1255, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1256(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1256, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1257(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1257, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88592(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_2, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88593(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_3, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88594(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_4, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88595(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_5, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88596(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_6, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88597(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_7, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88598(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_8, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_88599(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_9, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_885910(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_10, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_885911(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_11, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_885913(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_13, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_koi8r(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_KOI8_R, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

/*
 * The following is the common kiconvstr function for the conversions from
 * single byte codeset to UTF-8.
 */
static size_t
kiconvstr_fr_sb(size_t id, uchar_t *ib, size_t *inlen, uchar_t *ob,
	size_t *outlen, int flag, int *errno)
{
	kiconv_to_utf8_tbl_comp_t *tbl;
	size_t ret_val;
	uchar_t *ibtail;
	uchar_t *obtail;
	size_t i;
	size_t k;
	int8_t sz;
	boolean_t do_not_ignore_null;

	if (id > KICONV_MAX_MAPPING_TBLID &&
	    (id < KICONV_TBLID_RANGE1_START || id > KICONV_TBLID_RANGE1_END)) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	ret_val = 0;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	tbl = (id == KICONV_TBLID_720) ?
	    (kiconv_to_utf8_tbl_comp_t *)cp720_to_u8_tbl :
	    (kiconv_to_utf8_tbl_comp_t *)to_u8_tbl[id];

	while (ib < ibtail) {
		if (*ib == '\0' && do_not_ignore_null)
			break;

		if (*ib < 0x80) {
			if (ob >= obtail) {
				*errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib++;
			continue;
		}

		k = *ib - 0x80;
		sz = u8_number_of_bytes[tbl[k].u8[0]];

		if (sz <= 0) {
			if (flag & KICONV_REPLACE_INVALID) {
				if ((obtail - ob) < 3) {
					*errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}

				/* Save KICONV_UTF8_REPLACEMENT_CHAR. */
				*ob++ = 0xef;
				*ob++ = 0xbf;
				*ob++ = 0xbd;
				ret_val++;
				ib++;

				continue;
			}

			*errno = EILSEQ;
			ret_val = (size_t)-1;
			break;
		}

		if ((obtail - ob) < sz) {
			*errno = E2BIG;
			ret_val = (size_t)-1;
			break;
		}

		for (i = 0; i < sz; i++)
			*ob++ = tbl[k].u8[i];

		ib++;
	}

	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * The following 25 functions are the real entry points that will be
 * given to kiconv framework at the genunix.
 */
static size_t
kiconvstr_fr_720(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_720, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_737(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_737, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_852(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_852, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_857(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_857, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_862(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_862, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_866(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_866, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1250(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1250, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1251(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1251, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1253(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1253, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1254(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1254, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1255(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1255, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1256(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1256, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1257(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1257, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88592(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_2, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88593(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_3, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88594(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_4, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88595(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_5, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88596(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_6, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88597(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_7, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88598(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_8, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_88599(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_9, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_885910(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_10, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_885911(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_11, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_885913(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_13, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_koi8r(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_KOI8_R, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}


/*
 * The following are the supported code conversions that will be passed to
 * and registered from this module. The tocode and fromcode names are
 * normalized.
 */
#define	KICONV_MAX_EMEA_OPS		50

static kiconv_ops_t kiconv_emea_ops[KICONV_MAX_EMEA_OPS] = {
	{
		"utf8", "cp1250",
		open_fr_1250, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1250
	},
	{
		"cp1250", "utf8",
		open_to_1250, kiconv_to_sb, close_to_sb, kiconvstr_to_1250
	},
	{
		"utf8", "iso88592",
		open_fr_88592, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88592
	},
	{
		"iso88592", "utf8",
		open_to_88592, kiconv_to_sb, close_to_sb, kiconvstr_to_88592
	},
	{
		"utf8", "cp852",
		open_fr_852, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_852
	},
	{
		"cp852", "utf8",
		open_to_852, kiconv_to_sb, close_to_sb, kiconvstr_to_852
	},
	{
		"utf8", "cp1251",
		open_fr_1251, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1251
	},
	{
		"cp1251", "utf8",
		open_to_1251, kiconv_to_sb, close_to_sb, kiconvstr_to_1251
	},
	{
		"utf8", "iso88595",
		open_fr_88595, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88595
	},
	{
		"iso88595", "utf8",
		open_to_88595, kiconv_to_sb, close_to_sb, kiconvstr_to_88595
	},
	{
		"utf8", "koi8r",
		open_fr_koi8r, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_koi8r
	},
	{
		"koi8r", "utf8",
		open_to_koi8r, kiconv_to_sb, close_to_sb, kiconvstr_to_koi8r
	},
	{
		"utf8", "cp866",
		open_fr_866, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_866
	},
	{
		"cp866", "utf8",
		open_to_866, kiconv_to_sb, close_to_sb, kiconvstr_to_866
	},
	{
		"utf8", "cp1253",
		open_fr_1253, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1253
	},
	{
		"cp1253", "utf8",
		open_to_1253, kiconv_to_sb, close_to_sb, kiconvstr_to_1253
	},
	{
		"utf8", "iso88597",
		open_fr_88597, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88597
	},
	{
		"iso88597", "utf8",
		open_to_88597, kiconv_to_sb, close_to_sb, kiconvstr_to_88597
	},
	{
		"utf8", "cp737",
		open_fr_737, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_737
	},
	{
		"cp737", "utf8",
		open_to_737, kiconv_to_sb, close_to_sb, kiconvstr_to_737
	},
	{
		"utf8", "cp1254",
		open_fr_1254, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1254
	},
	{
		"cp1254", "utf8",
		open_to_1254, kiconv_to_sb, close_to_sb, kiconvstr_to_1254
	},
	{
		"utf8", "iso88599",
		open_fr_88599, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88599
	},
	{
		"iso88599", "utf8",
		open_to_88599, kiconv_to_sb, close_to_sb, kiconvstr_to_88599
	},
	{
		"utf8", "cp857",
		open_fr_857, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_857
	},
	{
		"cp857", "utf8",
		open_to_857, kiconv_to_sb, close_to_sb, kiconvstr_to_857
	},
	{
		"utf8", "cp1256",
		open_fr_1256, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1256
	},
	{
		"cp1256", "utf8",
		open_to_1256, kiconv_to_sb, close_to_sb, kiconvstr_to_1256
	},
	{
		"utf8", "iso88596",
		open_fr_88596, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88596
	},
	{
		"iso88596", "utf8",
		open_to_88596, kiconv_to_sb, close_to_sb, kiconvstr_to_88596
	},
	{
		"utf8", "cp720",
		open_fr_720, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_720
	},
	{
		"cp720", "utf8",
		open_to_720, kiconv_to_sb, close_to_sb, kiconvstr_to_720
	},
	{
		"utf8", "cp1255",
		open_fr_1255, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1255
	},
	{
		"cp1255", "utf8",
		open_to_1255, kiconv_to_sb, close_to_sb, kiconvstr_to_1255
	},
	{
		"utf8", "iso88598",
		open_fr_88598, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88598
	},
	{
		"iso88598", "utf8",
		open_to_88598, kiconv_to_sb, close_to_sb, kiconvstr_to_88598
	},
	{
		"utf8", "cp862",
		open_fr_862, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_862
	},
	{
		"cp862", "utf8",
		open_to_862, kiconv_to_sb, close_to_sb, kiconvstr_to_862
	},
	{
		"utf8", "cp1257",
		open_fr_1257, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1257
	},
	{
		"cp1257", "utf8",
		open_to_1257, kiconv_to_sb, close_to_sb, kiconvstr_to_1257
	},
	{
		"utf8", "iso885913",
		open_fr_885913, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_885913
	},
	{
		"iso885913", "utf8",
		open_to_885913, kiconv_to_sb, close_to_sb, kiconvstr_to_885913
	},
	{
		"utf8", "iso885910",
		open_fr_885910, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_885910
	},
	{
		"iso885910", "utf8",
		open_to_885910, kiconv_to_sb, close_to_sb, kiconvstr_to_885910
	},
	{
		"utf8", "iso885911",
		open_fr_885911, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_885911
	},
	{
		"iso885911", "utf8",
		open_to_885911, kiconv_to_sb, close_to_sb, kiconvstr_to_885911
	},
	{
		"utf8", "iso88593",
		open_fr_88593, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88593
	},
	{
		"iso88593", "utf8",
		open_to_88593, kiconv_to_sb, close_to_sb, kiconvstr_to_88593
	},
	{
		"utf8", "iso88594",
		open_fr_88594, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_88594
	},
	{
		"iso88594", "utf8",
		open_to_88594, kiconv_to_sb, close_to_sb, kiconvstr_to_88594
	},
};

static kiconv_module_info_t kiconv_emea_modinfo = {
	"kiconv_emea",		/* Must be the same as in kiconv framework. */
	KICONV_MAX_EMEA_OPS,	/* size_t kiconv_num_convs */
	kiconv_emea_ops,	/* kiconv_ops_t *kiconv_ops_tbl */
	0,			/* size_t kiconv_num_aliases */
	NULL,			/* char **aliases */
	NULL,			/* char **canonicals */
	0			/* int nowait */
};

static struct modlkiconv kiconv_emea = {
	&mod_kiconvops,
	"kiconv module for EMEA",
	&kiconv_emea_modinfo
};

static struct modlinkage linkage = {
	MODREV_1,
	(void *)&kiconv_emea,
	NULL
};

int
_init()
{
	int err;

	err = mod_install(&linkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_emea: failed to load kernel module");

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&linkage, modinfop));
}

int
_fini()
{
	int err;

	/*
	 * If this module is being used, then, we cannot remove the module.
	 * The following checking will catch pretty much all usual cases.
	 *
	 * Any remaining will be catached by the kiconv_unregister_module()
	 * during mod_remove() at below.
	 */
	if (kiconv_module_ref_count(KICONV_MODULE_ID_EMEA))
		return (EBUSY);

	err = mod_remove(&linkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_emea: failed to remove kernel module");

	return (err);
}
