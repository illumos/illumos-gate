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
 * Kernel iconv code conversion functions (PSARC/2007/173).
 *
 * Man pages: kiconv_open(9F), kiconv(9F), kiconv_close(9F), and kiconvstr(9F).
 * Interface stability: Committed.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/byteorder.h>
#include <sys/errno.h>
#include <sys/kiconv.h>
#include <sys/kiconv_latin1.h>


/*
 * The following macros indicate ids to the correct code conversion mapping
 * data tables to use. The actual tables are coming from <sys/kiconv_latin1.h>.
 */
#define	KICONV_TBLID_1252		(0x00)
#define	KICONV_TBLID_8859_1		(0x01)
#define	KICONV_TBLID_8859_15		(0x02)
#define	KICONV_TBLID_850		(0x03)

#define	KICONV_MAX_MAPPING_TBLID	(0x03)

/*
 * The following tables are coming from u8_textprep.c. We use them to
 * check on validity of UTF-8 characters and their bytes.
 */
extern const int8_t u8_number_of_bytes[];
extern const uint8_t u8_valid_min_2nd_byte[];
extern const uint8_t u8_valid_max_2nd_byte[];


/*
 * The following four functions, open_to_1252(), open_to_88591(),
 * open_to_885915(), and open_to_850(), are kiconv_open functions from
 * UTF-8 to corresponding single byte codesets.
 */
static void *
open_to_1252()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_1252;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_88591()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_1;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_885915()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_8859_15;
	s->bom_processed = 0;

	return ((void *)s);
}

static void *
open_to_850()
{
	kiconv_state_t s;

	s = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t), KM_SLEEP);
	s->id = KICONV_TBLID_850;
	s->bom_processed = 0;

	return ((void *)s);
}

/*
 * The following four functions, open_fr_1252(), open_fr_88591(),
 * open_fr_885915(), and open_fr_850(), are kiconv_open functions from
 * corresponding single byte codesets to UTF-8.
 */
static void *
open_fr_1252()
{
	return ((void *)KICONV_TBLID_1252);
}

static void *
open_fr_88591()
{
	return ((void *)KICONV_TBLID_8859_1);
}

static void *
open_fr_885915()
{
	return ((void *)KICONV_TBLID_8859_15);
}

static void *
open_fr_850()
{
	return ((void *)KICONV_TBLID_850);
}

/*
 * The following close_to_sb() function is kiconv_close function for
 * the conversions from UTF-8 to single byte codesets. The close_fr_sb()
 * is kiconv_close function for the conversions from single byte codesets to
 * UTF-8.
 */
static int
close_to_sb(void *s)
{
	if (! s || s == (void *)-1)
		return (EBADF);

	kmem_free(s, sizeof (kiconv_state_data_t));

	return (0);
}

static int
close_fr_sb(void *s)
{
	if ((ulong_t)s > KICONV_MAX_MAPPING_TBLID)
		return (EBADF);

	return (0);
}

/*
 * The following is the common kiconv function for conversions from UTF-8
 * to single byte codesets.
 */
static size_t
kiconv_to_sb(void *kcd, char **inbuf, size_t *inbytesleft, char **outbuf,
	size_t *outbytesleft, int *errno)
{
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

	/*
	 * Get the table id we are going to use for the code conversion
	 * and let's double check on it.
	 */
	id = ((kiconv_state_t)kcd)->id;
	if (id > KICONV_MAX_MAPPING_TBLID) {
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
	 * The inital high value for the binary search we will be using
	 * shortly is a literal constant as of today but to be future proof,
	 * let's calculate it like the following at here.
	 */
	init_h = sizeof (to_sb_tbl[id]) / sizeof (kiconv_to_sb_tbl_comp_t) - 1;

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
		 * issue E2BIG error.
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
		 * Issue EINVAL error if input buffer has an incomplete
		 * character at the end of the buffer.
		 */
		if ((ibtail - ib) < sz) {
			*errno = EINVAL;
			ret_val = (size_t)-1;
			break;
		}

		/*
		 * We collect UTF-8 character bytes and also check if
		 * this is a valid UTF-8 character without any bogus bytes
		 * based on the latest UTF-8 binary representation.
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
			if (to_sb_tbl[id][i].u8 == u8)
				break;
			else if (to_sb_tbl[id][i].u8 < u8)
				l = i + 1;
			else
				h = i - 1;
		}

		if (to_sb_tbl[id][i].u8 == u8) {
			*ob++ = to_sb_tbl[id][i].sb;
		} else {
			/*
			 * If we don't find a character in the target
			 * codeset, we insert an ASCII replacement character
			 * at the output buffer and indicate such
			 * "non-identical" conversion by increasing the
			 * return value which is the non-identical conversion
			 * counter if bigger than 0.
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
 * The following is the common kiconv function from single byte codesets to
 * UTF-8.
 */
static size_t
kiconv_fr_sb(void *kcd, char **inbuf, size_t *inbytesleft, char **outbuf,
	size_t *outbytesleft, int *errno)
{
	size_t ret_val;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;
	size_t i;
	size_t k;
	int8_t sz;

	/* Check on the kiconv code conversion descriptor validity. */
	if ((ulong_t)kcd > KICONV_MAX_MAPPING_TBLID) {
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
		sz = u8_number_of_bytes[to_u8_tbl[(ulong_t)kcd][k].u8[0]];

		/*
		 * If sz <= 0, that means we don't have any assigned character
		 * at the code point, k + 0x80, of the single byte codeset
		 * which is the fromcode. In other words, the input buffer
		 * has an illegal character.
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
			*ob++ = to_u8_tbl[(ulong_t)kcd][k].u8[i];

		ib++;
	}

	*inbuf = (char *)ib;
	*inbytesleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbytesleft = obtail - ob;

	return (ret_val);
}

/*
 * The following is the common kiconvstr function from UTF-8 to single byte
 * codesets.
 */
static size_t
kiconvstr_to_sb(size_t id, uchar_t *ib, size_t *inlen, uchar_t *ob,
	size_t *outlen, int flag, int *errno)
{
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

	/* Let's make sure that the table id is within the valid boundary. */
	if (id > KICONV_MAX_MAPPING_TBLID) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	ret_val = 0;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);
	init_h = sizeof (to_sb_tbl[id]) / sizeof (kiconv_to_sb_tbl_comp_t) - 1;

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
			if (to_sb_tbl[id][i].u8 == u8)
				break;
			else if (to_sb_tbl[id][i].u8 < u8)
				l = i + 1;
			else
				h = i - 1;
		}

		if (to_sb_tbl[id][i].u8 == u8) {
			*ob++ = to_sb_tbl[id][i].sb;
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
 * The following four functions are entry points recorded at the conv_list[]
 * defined at below.
 */
static size_t
kiconvstr_to_1252(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_1252, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_1(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_1, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_15(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_8859_15, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_to_850(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_to_sb(KICONV_TBLID_850, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

/*
 * The following is the common kiconvstr function for conversions from
 * single byte codesets to UTF-8.
 */
static size_t
kiconvstr_fr_sb(size_t id, uchar_t *ib, size_t *inlen, uchar_t *ob,
	size_t *outlen, int flag, int *errno)
{
	size_t ret_val;
	uchar_t *ibtail;
	uchar_t *obtail;
	size_t i;
	size_t k;
	int8_t sz;
	boolean_t do_not_ignore_null;

	ret_val = 0;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

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
		sz = u8_number_of_bytes[to_u8_tbl[id][k].u8[0]];

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
			*ob++ = to_u8_tbl[id][k].u8[i];

		ib++;
	}

	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * The following four functions are also entry points recorded at
 * the conv_list[] at below.
 */
static size_t
kiconvstr_fr_1252(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_1252, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_1(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_1, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_15(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_8859_15, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

static size_t
kiconvstr_fr_850(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return (kiconvstr_fr_sb(KICONV_TBLID_850, (uchar_t *)inarray,
	    inlen, (uchar_t *)outarray, outlen, flag, errno));
}

/*
 * The following static vector contains the normalized code names
 * and their corresponding code ids. They are somewhat arbitrarily ordered
 * based on marketing data available. A code id could repeat for aliases.
 *
 * The vector was generated by using a small utility program called
 * codeidlistgen.c that you can find from PSARC/2007/173/materials/util/.
 *
 * The code ids must be portable, i.e., if needed, you can always generate
 * the code_list[] again with different code ids. You'll also need to
 * update the conv_list[] at below.
 */
#define	KICONV_MAX_CODEID_ENTRY		68
#define	KICONV_MAX_CODEID		42

static kiconv_code_list_t code_list[KICONV_MAX_CODEID_ENTRY] = {
	{ "utf8", 0 },
	{ "cp1252", 1 },
	{ "1252", 1 },
	{ "iso88591", 2 },
	{ "iso885915", 3 },
	{ "cp850", 4 },
	{ "850", 4 },
	{ "eucjp", 5 },
	{ "eucjpms", 6 },
	{ "cp932", 7 },
	{ "932", 7 },
	{ "shiftjis", 8 },
	{ "pck", 8 },
	{ "sjis", 8 },
	{ "gb18030", 9 },
	{ "gbk", 10 },
	{ "cp936", 10 },
	{ "936", 10 },
	{ "euccn", 11 },
	{ "euckr", 12 },
	{ "unifiedhangul", 13 },
	{ "cp949", 13 },
	{ "949", 13 },
	{ "big5", 14 },
	{ "cp950", 14 },
	{ "950", 14 },
	{ "big5hkscs", 15 },
	{ "euctw", 16 },
	{ "cp950hkscs", 17 },
	{ "cp1250", 18 },
	{ "1250", 18 },
	{ "iso88592", 19 },
	{ "cp852", 20 },
	{ "852", 20 },
	{ "cp1251", 21 },
	{ "1251", 21 },
	{ "iso88595", 22 },
	{ "koi8r", 23 },
	{ "cp866", 24 },
	{ "866", 24 },
	{ "cp1253", 25 },
	{ "1253", 25 },
	{ "iso88597", 26 },
	{ "cp737", 27 },
	{ "737", 27 },
	{ "cp1254", 28 },
	{ "1254", 28 },
	{ "iso88599", 29 },
	{ "cp857", 30 },
	{ "857", 30 },
	{ "cp1256", 31 },
	{ "1256", 31 },
	{ "iso88596", 32 },
	{ "cp720", 33 },
	{ "720", 33 },
	{ "cp1255", 34 },
	{ "1255", 34 },
	{ "iso88598", 35 },
	{ "cp862", 36 },
	{ "862", 36 },
	{ "cp1257", 37 },
	{ "1257", 37 },
	{ "iso885913", 38 },
	{ "iso885910", 39 },
	{ "iso885911", 40 },
	{ "tis620", 40 },
	{ "iso88593", 41 },
	{ "iso88594", 42 },
};

/*
 * The list of code conversions supported are grouped together per
 * module which will be loaded as needed.
 */
#define	KICONV_MAX_CONVERSIONS		84

static kiconv_conv_list_t conv_list[KICONV_MAX_CONVERSIONS] = {
	/* Embedded code conversions: */
	{
		1, 0, KICONV_EMBEDDED,
		open_to_1252, kiconv_to_sb, close_to_sb, kiconvstr_to_1252
	},
	{
		0, 1, KICONV_EMBEDDED,
		open_fr_1252, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1252
	},
	{
		2, 0, KICONV_EMBEDDED,
		open_to_88591, kiconv_to_sb, close_to_sb, kiconvstr_to_1
	},
	{
		0, 2, KICONV_EMBEDDED,
		open_fr_88591, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_1
	},
	{
		3, 0, KICONV_EMBEDDED,
		open_to_885915, kiconv_to_sb, close_to_sb, kiconvstr_to_15
	},
	{
		0, 3, KICONV_EMBEDDED,
		open_fr_885915, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_15
	},
	{
		4, 0, KICONV_EMBEDDED,
		open_to_850, kiconv_to_sb, close_to_sb, kiconvstr_to_850
	},
	{
		0, 4, KICONV_EMBEDDED,
		open_fr_850, kiconv_fr_sb, close_fr_sb, kiconvstr_fr_850
	},

	/* kiconv_ja module conversions: */
	{ 0, 5, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 5, 0, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 0, 6, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 6, 0, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 0, 7, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 7, 0, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 0, 8, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },
	{ 8, 0, KICONV_MODULE_ID_JA, NULL, NULL, NULL, NULL },

	/* kiconv_sc module conversions: */
	{ 0, 9, KICONV_MODULE_ID_SC, NULL, NULL, NULL, NULL },
	{ 9, 0, KICONV_MODULE_ID_SC, NULL, NULL, NULL, NULL },
	{ 0, 10, KICONV_MODULE_ID_SC, NULL, NULL, NULL, NULL },
	{ 10, 0, KICONV_MODULE_ID_SC, NULL, NULL, NULL, NULL },
	{ 0, 11, KICONV_MODULE_ID_SC, NULL, NULL, NULL, NULL },
	{ 11, 0, KICONV_MODULE_ID_SC, NULL, NULL, NULL, NULL },

	/* kiconv_ko module conversions: */
	{ 0, 12, KICONV_MODULE_ID_KO, NULL, NULL, NULL, NULL },
	{ 12, 0, KICONV_MODULE_ID_KO, NULL, NULL, NULL, NULL },
	{ 0, 13, KICONV_MODULE_ID_KO, NULL, NULL, NULL, NULL },
	{ 13, 0, KICONV_MODULE_ID_KO, NULL, NULL, NULL, NULL },

	/* kiconv_tc module conversions: */
	{ 0, 14, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 14, 0, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 0, 15, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 15, 0, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 0, 16, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 16, 0, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 0, 17, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },
	{ 17, 0, KICONV_MODULE_ID_TC, NULL, NULL, NULL, NULL },

	/* kiconv_emea module conversions: */
	{ 0, 18, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 18, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 19, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 19, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 20, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 20, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 21, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 21, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 22, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 22, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 23, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 23, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 24, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 24, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 25, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 25, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 26, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 26, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 27, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 27, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 28, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 28, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 29, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 29, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 30, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 30, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 31, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 31, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 32, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 32, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 33, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 33, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 34, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 34, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 35, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 35, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 36, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 36, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 37, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 37, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 38, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 38, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 39, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 39, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 40, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 40, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 41, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 41, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 0, 42, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
	{ 42, 0, KICONV_MODULE_ID_EMEA, NULL, NULL, NULL, NULL },
};

/* The list of implemeted and supported modules. */
static kiconv_mod_list_t module_list[KICONV_MAX_MODULE_ID + 1] = {
	"kiconv_embedded", 0,
	"kiconv_ja", 0,
	"kiconv_sc", 0,
	"kiconv_ko", 0,
	"kiconv_tc", 0,
	"kiconv_emea", 0,
};

/*
 * We use conv_list_lock to restrict data access of both conv_list[] and
 * module_list[] as they are tightly coupled critical sections that need to be
 * dealt together as a unit.
 */
static kmutex_t conv_list_lock;

void
kiconv_init()
{
	mutex_init(&conv_list_lock, NULL, MUTEX_DEFAULT, NULL);
}

/*
 * The following is used to check on whether a kiconv module is being
 * used or not at the _fini() of the module.
 */
size_t
kiconv_module_ref_count(size_t mid)
{
	int count;

	if (mid <= 0 || mid > KICONV_MAX_MODULE_ID)
		return (0);

	mutex_enter(&conv_list_lock);

	count = module_list[mid].refcount;

	mutex_exit(&conv_list_lock);

	return (count);
}

/*
 * This function "normalizes" a given code name, n, by not including skippable
 * characters and folding uppercase letters to corresponding lowercase letters.
 * We only fold 7-bit ASCII uppercase characters since the names should be in
 * Portable Character Set of 7-bit ASCII.
 *
 * By doing this, we will be able to maximize the code name matches.
 */
static size_t
normalize_codename(const char *n)
{
	char s[KICONV_MAX_CODENAME_LEN + 1];
	size_t i;

	if (n == NULL)
		return ((size_t)-1);

	for (i = 0; *n; n++) {
		if (KICONV_SKIPPABLE_CHAR(*n))
			continue;

		/* If unreasonably lengthy, we don't support such names. */
		if (i >= KICONV_MAX_CODENAME_LEN)
			return ((size_t)-1);

		s[i++] = (*n >= 'A' && *n <= 'Z') ? *n - 'A' + 'a' : *n;
	}
	s[i] = '\0';

	/* With the normalized name, find the corresponding codeset id. */
	for (i = 0; i < KICONV_MAX_CODEID_ENTRY; i++)
		if (strcmp(s, code_list[i].name) == 0)
			return (code_list[i].id);

	/*
	 * In future time, we will also have a few more lines of code at below
	 * that will deal with other user-created modules' fromcodes and
	 * tocodes including aliases in a different vector. For now, we don't
	 * support that but only the known names to this project at this time.
	 */

	return ((size_t)-1);
}

/*
 * This function called from mod_install() registers supplied code
 * conversions. At this point, it does not honor aliases and hence does not
 * use nowait data field from the kiconv module info data structure.
 */
int
kiconv_register_module(kiconv_module_info_t *info)
{
	size_t mid;
	size_t fid;
	size_t tid;
	size_t i;
	size_t j;
	kiconv_ops_t *op;

	/* Validate the given kiconv module info. */
	if (info == NULL || info->module_name == NULL ||
	    info->kiconv_num_convs == 0 || info->kiconv_ops_tbl == NULL)
		return (EINVAL);

	/*
	 * Check if this is one of the known modules. At this point,
	 * we do not allow user-defined kiconv modules and that'd be for
	 * a future project.
	 */
	for (mid = 1; mid <= KICONV_MAX_MODULE_ID; mid++)
		if (strcmp(module_list[mid].name, info->module_name) == 0)
			break;
	if (mid > KICONV_MAX_MODULE_ID)
		return (EINVAL);

	/* Let's register the conversions supplied. */
	mutex_enter(&conv_list_lock);

	/*
	 * This is very unlikely situation but by any chance we don't want to
	 * register a module that is already in.
	 */
	if (module_list[mid].refcount > 0) {
		mutex_exit(&conv_list_lock);
		return (EAGAIN);
	}

	for (i = 0; i < info->kiconv_num_convs; i++) {
		op = &(info->kiconv_ops_tbl[i]);

		fid = normalize_codename(op->fromcode);
		tid = normalize_codename(op->tocode);

		/*
		 * If we find anything wrong in this particular conversion,
		 * we skip this one and continue to the next one. This include
		 * a case where there is a conversion already being assigned
		 * into the conv_list[] somehow, i.e., new one never kicks out
		 * old one.
		 */
		if (op->kiconv_open == NULL || op->kiconv == NULL ||
		    op->kiconv_close == NULL || op->kiconvstr == NULL)
			continue;

		for (j = 0; j < KICONV_MAX_CONVERSIONS; j++) {
			if (conv_list[j].mid == mid &&
			    conv_list[j].fid == fid &&
			    conv_list[j].tid == tid) {
				if (conv_list[j].open == NULL) {
					conv_list[j].open = op->kiconv_open;
					conv_list[j].kiconv = op->kiconv;
					conv_list[j].close = op->kiconv_close;
					conv_list[j].kiconvstr = op->kiconvstr;
				}
				break;
			}
		}
	}

	mutex_exit(&conv_list_lock);

	return (0);
}

/*
 * The following function called during mod_remove() will try to unregister,
 * i.e., clear up conversion function pointers, from the conv_list[] if it
 * can. If there is any code conversions being used, then, the function will
 * just return EBUSY indicating that the module cannot be unloaded.
 */
int
kiconv_unregister_module(kiconv_module_info_t *info)
{
	size_t mid;
	size_t i;

	if (info == NULL || info->module_name == NULL ||
	    info->kiconv_num_convs == 0 || info->kiconv_ops_tbl == NULL)
		return (EINVAL);

	for (mid = 1; mid <= KICONV_MAX_MODULE_ID; mid++)
		if (strcmp(module_list[mid].name, info->module_name) == 0)
			break;
	if (mid > KICONV_MAX_MODULE_ID)
		return (EINVAL);

	mutex_enter(&conv_list_lock);

	/*
	 * If any of the conversions are used, then, this module canont be
	 * unloaded.
	 */
	if (module_list[mid].refcount > 0) {
		mutex_exit(&conv_list_lock);
		return (EBUSY);
	}

	/*
	 * Otherwise, we unregister all conversions from this module
	 * and be ready for the unloading. At this point, we only care about
	 * the conversions we know about with the module.
	 */
	for (i = 0; i < KICONV_MAX_CONVERSIONS; i++) {
		if (conv_list[i].mid == mid) {
			conv_list[i].open = NULL;
			conv_list[i].kiconv = NULL;
			conv_list[i].close = NULL;
			conv_list[i].kiconvstr = NULL;
		}
	}

	mutex_exit(&conv_list_lock);

	return (0);
}

/*
 * The following function check if asked code conversion is available
 * and if necessary, load the corresponding kiconv module that contains
 * the conversion (and others).
 */
static kiconv_t
check_and_load_conversions(const char *tocode, const char *fromcode)
{
	kiconv_t kcd;
	size_t tid;
	size_t fid;
	size_t mid;
	size_t i;

	/* Normalize the given names and find the corresponding code ids. */
	tid = normalize_codename(tocode);
	if (tid == (size_t)-1)
		return ((kiconv_t)-1);

	fid = normalize_codename(fromcode);
	if (fid == (size_t)-1)
		return ((kiconv_t)-1);

	/*
	 * Search the conversion.
	 *
	 * If the conversion isn't supported, just return -1.
	 * If the conversion is supported but there is no corresponding
	 * module loaded, try to load it and if successful, return
	 * a kiconv conversion descriptor memory block.
	 *
	 * We maintain a reference counter of uint_t for each module.
	 */
	mutex_enter(&conv_list_lock);

	for (i = 0; i < KICONV_MAX_CONVERSIONS; i++)
		if (conv_list[i].tid == tid && conv_list[i].fid == fid)
			break;
	if (i >= KICONV_MAX_CONVERSIONS) {
		mutex_exit(&conv_list_lock);
		return ((kiconv_t)-1);
	}

	mid = conv_list[i].mid;

	if (conv_list[i].open == NULL) {
		mutex_exit(&conv_list_lock);

		if (modload("kiconv", module_list[mid].name) < 0)
			return ((kiconv_t)-1);

		/*
		 * Let's double check if something happened right after
		 * the modload and/or if the module really has the conversion.
		 */
		mutex_enter(&conv_list_lock);

		if (conv_list[i].open == NULL) {
			mutex_exit(&conv_list_lock);
			return ((kiconv_t)-1);
		}
	}

	/*
	 * If we got the conversion, we will use the conversion function
	 * in the module and so let's increase the module's refcounter
	 * so that the module won't be kicked out. (To be more exact and
	 * specific, the "refcount" is thus the reference counter of
	 * the module functions being used.)
	 */
	if (module_list[mid].refcount < UINT_MAX)
		module_list[mid].refcount++;

	mutex_exit(&conv_list_lock);

	kcd = (kiconv_t)kmem_alloc(sizeof (kiconv_data_t), KM_SLEEP);
	kcd->handle = (void *)-1;
	kcd->id = i;

	return (kcd);
}

/*
 * The following are the four "Committed" interfaces.
 */
kiconv_t
kiconv_open(const char *tocode, const char *fromcode)
{
	kiconv_t kcd;
	size_t mid;

	kcd = check_and_load_conversions(tocode, fromcode);
	if (kcd == (kiconv_t)-1)
		return ((kiconv_t)-1);

	kcd->handle = (conv_list[kcd->id].open)();
	if (kcd->handle == (void *)-1) {
		/*
		 * If the conversion couldn't be opened for some reason,
		 * then, we unallocate the kcd and, more importantly, before
		 * that, we also decrease the module reference counter.
		 */
		mid = conv_list[kcd->id].mid;

		mutex_enter(&conv_list_lock);

		if (module_list[mid].refcount > 0)
			module_list[mid].refcount--;

		mutex_exit(&conv_list_lock);

		kmem_free((void *)kcd, sizeof (kiconv_data_t));

		return ((kiconv_t)-1);
	}

	return (kcd);
}

size_t
kiconv(kiconv_t kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	/* Do some minimum checking on the kiconv conversion descriptor. */
	if (! kcd || kcd == (kiconv_t)-1 || conv_list[kcd->id].kiconv == NULL) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	return ((conv_list[kcd->id].kiconv)(kcd->handle, inbuf, inbytesleft,
	    outbuf, outbytesleft, errno));
}

int
kiconv_close(kiconv_t kcd)
{
	int ret;
	size_t mid;

	if (! kcd || kcd == (kiconv_t)-1 || conv_list[kcd->id].close == NULL)
		return (EBADF);

	mid = conv_list[kcd->id].mid;

	ret = (conv_list[kcd->id].close)(kcd->handle);

	kmem_free((void *)kcd, sizeof (kiconv_data_t));

	mutex_enter(&conv_list_lock);

	/*
	 * While we maintain reference conter for each module, once loaded,
	 * we don't modunload from kiconv functions even if the counter
	 * reaches back to zero.
	 */
	if (module_list[mid].refcount > 0)
		module_list[mid].refcount--;

	mutex_exit(&conv_list_lock);

	return (ret);
}

size_t
kiconvstr(const char *tocode, const char *fromcode, char *inarray,
	size_t *inlen, char *outarray, size_t *outlen, int flag, int *errno)
{
	kiconv_t kcd;
	size_t ret;
	size_t mid;

	kcd = check_and_load_conversions(tocode, fromcode);
	if (kcd == (kiconv_t)-1 || conv_list[kcd->id].kiconvstr == NULL) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	mid = conv_list[kcd->id].mid;

	ret = (conv_list[kcd->id].kiconvstr)(inarray, inlen, outarray, outlen,
	    flag, errno);

	kmem_free((void *)kcd, sizeof (kiconv_data_t));

	mutex_enter(&conv_list_lock);

	if (module_list[mid].refcount > 0)
		module_list[mid].refcount--;

	mutex_exit(&conv_list_lock);

	return (ret);
}
