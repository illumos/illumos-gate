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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/byteorder.h>
#include <sys/errno.h>
#include <sys/euc.h>
#include <sys/modctl.h>
#include <sys/kiconv.h>

#include <sys/kiconv_ja.h>
#include <sys/kiconv_ja_jis_to_unicode.h>
#include <sys/kiconv_ja_unicode_to_jis.h>

/*
 * The following vector shows remaining bytes in a UTF-8 character.
 * Index will be the first byte of the character. This is defined in
 * u8_textprep.c.
 */
extern const int8_t u8_number_of_bytes[];

/*
 * The following is a vector of bit-masks to get used bits in
 * the first byte of a UTF-8 character. Index is remaining bytes at above of
 * the character. This is defined in uconv.c.
 */
extern const uchar_t u8_masks_tbl[];

/*
 * The following two vectors are to provide valid minimum and
 * maximum values for the 2'nd byte of a multibyte UTF-8 character for
 * better illegal sequence checking. The index value must be the value of
 * the first byte of the UTF-8 character. These are defined in u8_textprep.c.
 */
extern const uint8_t u8_valid_min_2nd_byte[];
extern const uint8_t u8_valid_max_2nd_byte[];

static kiconv_ja_euc16_t
kiconv_ja_ucs2_to_euc16(kiconv_ja_ucs2_t ucs2)
{
	const kiconv_ja_euc16_t	*p;

	if ((p = kiconv_ja_ucs2_to_euc16_index[ucs2 >> 8]) != NULL)
		return (p[ucs2 & 0xff]);

	return (KICONV_JA_NODEST);
}

static size_t
utf8_ucs(uint_t *p, uchar_t **pip, size_t *pileft, int *errno)
{
	uint_t	l;		/* to be copied to *p on successful return */
	uchar_t	ic;		/* current byte */
	uchar_t	ic1;		/* 1st byte */
	uchar_t	*ip = *pip;	/* next byte to read */
	size_t	ileft = *pileft; /* number of bytes available */
	size_t	rv = 0;		/* return value of this function */
	int	remaining_bytes;
	int	u8_size;

	KICONV_JA_NGET(ic1);	/* read 1st byte */

	if (ic1 < 0x80) {
		/* successfully converted */
		*p = (uint_t)ic1;
		goto ret;
	}

	u8_size = u8_number_of_bytes[ic1];
	if (u8_size == U8_ILLEGAL_CHAR) {
		KICONV_JA_RETERROR(EILSEQ)
	} else if (u8_size == U8_OUT_OF_RANGE_CHAR) {
		KICONV_JA_RETERROR(ERANGE)
	}

	remaining_bytes = u8_size - 1;
	if (remaining_bytes != 0) {
		l = ic1 & u8_masks_tbl[remaining_bytes];

		for (; remaining_bytes > 0; remaining_bytes--) {
			KICONV_JA_NGET(ic);
			if (ic1 != 0U) {
				if ((ic < u8_valid_min_2nd_byte[ic1]) ||
				    (ic > u8_valid_max_2nd_byte[ic1])) {
					KICONV_JA_RETERROR(EILSEQ)
				}
				ic1 = 0U; /* 2nd byte check done */
			} else {
				if ((ic < 0x80) || (ic > 0xbf)) {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
			l = (l << 6) | (ic & 0x3f);
		}

		/* successfully converted */
		*p = l;
	} else {
		KICONV_JA_RETERROR(EILSEQ)
	}

ret:
	if (rv == 0) {
		/*
		 * Update rv, *pip, and *pileft on successfule return.
		 */
		rv = *pileft - ileft;
		*pip = ip;
		*pileft = ileft;
	}

	return (rv);
}

static size_t
utf8_ucs_replace(uint_t *p, uchar_t **pip, size_t *pileft, size_t *repnum)
{
	uint_t	l;		/* to be copied to *p on successful return */
	uchar_t	ic;		/* current byte */
	uchar_t	ic1;		/* 1st byte */
	uchar_t	*ip = *pip;	/* next byte to read */
	size_t	ileft = *pileft; /* number of bytes available */
	size_t	rv = 0;		/* return value of this function */
	int	remaining_bytes;
	int	u8_size;

	KICONV_JA_NGET_REP_TO_MB(ic1);	/* read 1st byte */

	if (ic1 < 0x80) {
		/* successfully converted */
		l = (uint_t)ic1;
		goto ret;
	}

	u8_size = u8_number_of_bytes[ic1];
	if (u8_size == U8_ILLEGAL_CHAR || u8_size == U8_OUT_OF_RANGE_CHAR) {
		l = KICONV_JA_DEF_SINGLE;
		(*repnum)++;
		goto ret;
	}

	remaining_bytes = u8_size - 1;

	if (remaining_bytes != 0) {
		l = ic1 & u8_masks_tbl[remaining_bytes];

		for (; remaining_bytes > 0; remaining_bytes--) {
			KICONV_JA_NGET_REP_TO_MB(ic);
			if (ic1 != 0U) {
				if ((ic < u8_valid_min_2nd_byte[ic1]) ||
				    (ic > u8_valid_max_2nd_byte[ic1])) {
					l = KICONV_JA_DEF_SINGLE;
					(*repnum)++;
					ileft -= (remaining_bytes - 1);
					ip += (remaining_bytes - 1);
					break;
				}
				ic1 = 0U; /* 2nd byte check done */
			} else {
				if ((ic < 0x80) || (ic > 0xbf)) {
					l = KICONV_JA_DEF_SINGLE;
					(*repnum)++;
					ileft -= (remaining_bytes - 1);
					ip += (remaining_bytes - 1);
					break;
				}
			}
			l = (l << 6) | (ic & 0x3f);
		}
	} else {
		l = KICONV_JA_DEF_SINGLE;
		(*repnum)++;
	}

ret:
	/* successfully converted */
	*p = l;
	rv = *pileft - ileft;

	*pip = ip;
	*pileft = ileft;

	return (rv);
}

static size_t				/* return #bytes read, or -1 */
read_unicode(
	uint_t	*p,		/* point variable to store UTF-32 */
	uchar_t	**pip,		/* point pointer to input buf */
	size_t	*pileft,	/* point #bytes left in input buf */
	int	*errno,		/* point variable to errno */
	int	flag,		/* kiconvstr flag */
	size_t	*rv)		/* point return valuse */
{
	if (flag & KICONV_REPLACE_INVALID)
		return (utf8_ucs_replace(p, pip, pileft, rv));
	else
		return (utf8_ucs(p, pip, pileft, errno));
}

static size_t
write_unicode(
	uint_t	u32,		/* UTF-32 to write */
	char	**pop,		/* point pointer to output buf */
	size_t	*poleft,	/* point #bytes left in output buf */
	int	*errno)		/* point variable to errno */
{
	char	*op = *pop;
	size_t	oleft = *poleft;
	size_t	rv = 0;			/* return value */

	if (u32 <= 0x7f) {
		KICONV_JA_NPUT((uchar_t)(u32));
		rv = 1;
	} else if (u32 <= 0x7ff) {
		KICONV_JA_NPUT((uchar_t)((((u32)>>6) & 0x1f) | 0xc0));
		KICONV_JA_NPUT((uchar_t)(((u32) & 0x3f) | 0x80));
		rv = 2;
	} else if ((u32 >= 0xd800) && (u32 <= 0xdfff)) {
		KICONV_JA_RETERROR(EILSEQ)
	} else if (u32 <= 0xffff) {
		KICONV_JA_NPUT((uchar_t)((((u32)>>12) & 0x0f) | 0xe0));
		KICONV_JA_NPUT((uchar_t)((((u32)>>6) & 0x3f) | 0x80));
		KICONV_JA_NPUT((uchar_t)(((u32) & 0x3f) | 0x80));
		rv = 3;
	} else if (u32 <= 0x10ffff) {
		KICONV_JA_NPUT((uchar_t)((((u32)>>18) & 0x07) | 0xf0));
		KICONV_JA_NPUT((uchar_t)((((u32)>>12) & 0x3f) | 0x80));
		KICONV_JA_NPUT((uchar_t)((((u32)>>6) & 0x3f) | 0x80));
		KICONV_JA_NPUT((uchar_t)(((u32) & 0x3f) | 0x80));
		rv = 4;
	} else {
		KICONV_JA_RETERROR(EILSEQ)
	}

ret:
	if (rv != (size_t)-1) {
		/* update *pop and *poleft only on successful return */
		*pop = op;
		*poleft = oleft;
	}

	return (rv);
}

static void *
_kiconv_ja_open_unicode(uint8_t id)
{
	kiconv_state_t	kcd;

	kcd = (kiconv_state_t)kmem_alloc(sizeof (kiconv_state_data_t),
	    KM_SLEEP);
	kcd->id = id;
	kcd->bom_processed = 0;
	return ((void *)kcd);
}

static void *
open_eucjp(void)
{
	return (_kiconv_ja_open_unicode(KICONV_JA_TBLID_EUCJP));
}

static void *
open_eucjpms(void)
{
	return (_kiconv_ja_open_unicode(KICONV_JA_TBLID_EUCJP_MS));
}

static void *
open_sjis(void)
{
	return (_kiconv_ja_open_unicode(KICONV_JA_TBLID_SJIS));
}

static void *
open_cp932(void)
{
	return (_kiconv_ja_open_unicode(KICONV_JA_TBLID_CP932));
}

int
close_ja(void *kcd)
{
	if (! kcd || kcd == (void *)-1)
		return (EBADF);

	kmem_free(kcd, sizeof (kiconv_state_data_t));

	return (0);
}

static size_t
_do_kiconv_fr_eucjp(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uint_t		u32;		/* UTF-32 */
	uint_t		index;		/* index for table lookup */
	uchar_t		ic1, ic2, ic3;	/* 1st, 2nd, and 3rd bytes of a char */
	size_t		rv = 0;		/* return value of this function */

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;
	size_t		id = ((kiconv_state_t)kcd)->id;

	if ((inbuf == NULL) || (*inbuf == NULL)) {
		return (0);
	}

	ip = (uchar_t *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		KICONV_JA_NGET(ic1);		/* get 1st byte */

		if (KICONV_JA_ISASC(ic1)) {	/* ASCII; 1 byte */
			u32 = kiconv_ja_jisx0201roman_to_ucs2[ic1];
			KICONV_JA_PUTU(u32);
		} else if (KICONV_JA_ISCS1(ic1)) { /* 0208 or UDC; 2 bytes */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISCS1(ic2)) { /* 2nd byte check passed */
				ic1 &= KICONV_JA_CMASK;
				ic2 &= KICONV_JA_CMASK;
				KICONV_JA_CNV_JISMS_TO_U2(id, u32, ic1, ic2);
				if (u32 == KICONV_JA_NODEST) {
					index = (ic1 - 0x21) * 94 + ic2 - 0x21;
					u32 = kiconv_ja_jisx0208_to_ucs2[index];
				}
				if (u32 == KICONV_JA_REPLACE)
					rv++;
				KICONV_JA_PUTU(u32);
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
			}
		} else if (ic1 == SS2) { /* JIS X 0201 Kana; 2 bytes */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISCS2(ic2)) { /* 2nd byte check passed */
				index = (ic2 - 0xa1);
				u32 = kiconv_ja_jisx0201kana_to_ucs2[index];
				KICONV_JA_PUTU(u32);
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
			}
		} else if (ic1 == SS3) { /* JIS X 0212 or UDC; 3 bytes */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISCS3(ic2)) { /* 2nd byte check passed */
				KICONV_JA_NGET(ic3);
				if (KICONV_JA_ISCS3(ic3)) {
					/* 3rd byte check passed */
					ic2 &= KICONV_JA_CMASK;
					ic3 &= KICONV_JA_CMASK;
					KICONV_JA_CNV_JIS0212MS_TO_U2(id, u32,
					    ic2, ic3);
					if (u32 == KICONV_JA_NODEST) {
						index = ((ic2 - 0x21) * 94 +
						    (ic3 - 0x21));
						u32 = kiconv_ja_jisx0212_to_ucs2
						    [index];
					}
					if (u32 == KICONV_JA_REPLACE)
						rv++;
					KICONV_JA_PUTU(u32);
				} else { /* 3rd byte check failed */
					KICONV_JA_RETERROR(EILSEQ)
				}
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
			}
		} else if (KICONV_JA_ISC1CTRLEUC(ic1)) {
			/* C1 control; 1 byte */
			u32 = ic1;
			KICONV_JA_PUTU(u32);
		} else { /* 1st byte check failed */
			KICONV_JA_RETERROR(EILSEQ)
		}

		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbuf = (char *)ip;
		*inbytesleft = ileft;
		*outbuf = op;
		*outbytesleft = oleft;
	}

ret:
	return (rv);
}

static size_t
_do_kiconv_to_eucjp(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uchar_t		ic;
	size_t		rv = 0;
	uint_t		ucs4;
	ushort_t	euc16;

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;
	size_t		read_len;

	size_t		id = ((kiconv_state_t)kcd)->id;

	if ((inbuf == NULL) || (*inbuf == NULL)) {
		return (0);
	}

	ip = (uchar_t *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	KICONV_JA_CHECK_UTF8_BOM(ip, ileft);

	while (ileft != 0) {
		KICONV_JA_GETU(&ucs4, 0);

		if (ucs4 > 0xffff) {
			/* non-BMP */
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		KICONV_JA_CNV_U2_TO_EUCJPMS(id, euc16, ucs4);
		if (euc16 == KICONV_JA_NODEST) {
			euc16 = kiconv_ja_ucs2_to_euc16((ushort_t)ucs4);
		}
		if (euc16 == KICONV_JA_NODEST) {
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		switch (euc16 & 0x8080) {
		case 0x0000:	/* CS0 */
			ic = (uchar_t)euc16;
			KICONV_JA_NPUT(ic);
			break;
		case 0x8080:	/* CS1 */
			ic = (uchar_t)((euc16 >> 8) & 0xff);
			KICONV_JA_NPUT(ic);
			ic = (uchar_t)(euc16 & 0xff);
			KICONV_JA_NPUT(ic);
			break;
		case 0x0080:	/* CS2 */
			KICONV_JA_NPUT(SS2);
			ic = (uchar_t)euc16;
			KICONV_JA_NPUT(ic);
			break;
		case 0x8000:	/* CS3 */
			KICONV_JA_NPUT(SS3);
			ic = (uchar_t)((euc16 >> 8) & 0xff);
			KICONV_JA_NPUT(ic);
			ic = (uchar_t)(euc16 & KICONV_JA_CMASK);
			KICONV_JA_NPUT(ic | KICONV_JA_CMSB);
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
	}

ret:
	return (rv);
}

static size_t
_do_kiconvstr_fr_eucjp(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno, uint8_t id)
{
	uint_t		u32;		/* UTF-32 */
	uint_t		index;		/* index for table lookup */
	uchar_t		ic1, ic2, ic3;	/* 1st, 2nd, and 3rd bytes of a char */
	size_t		rv = 0;		/* return value of this function */

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;

	boolean_t do_not_ignore_null;

	if ((inbuf == NULL) || (*inbuf == '\0')) {
		return (0);
	}

	ip = (uchar_t *)inbuf;
	ileft = *inbytesleft;
	op = outbuf;
	oleft = *outbytesleft;

	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ileft != 0) {
		KICONV_JA_NGET(ic1);		/* get 1st byte */

		if (KICONV_JA_ISASC(ic1)) {	/* ASCII; 1 byte */
			if (ic1 == '\0' && do_not_ignore_null) {
				return (0);
			}
			u32 = kiconv_ja_jisx0201roman_to_ucs2[ic1];
			KICONV_JA_PUTU(u32);
		} else if (KICONV_JA_ISCS1(ic1)) { /* 0208 or UDC; 2 bytes */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISCS1(ic2)) { /* 2nd byte check passed */
				ic1 &= KICONV_JA_CMASK;
				ic2 &= KICONV_JA_CMASK;
				KICONV_JA_CNV_JISMS_TO_U2(id, u32, ic1, ic2);
				if (u32 == KICONV_JA_NODEST) {
					index = (ic1 - 0x21) * 94 + ic2 - 0x21;
					u32 = kiconv_ja_jisx0208_to_ucs2[index];
				}
				if (u32 == KICONV_JA_REPLACE)
					rv++;
				KICONV_JA_PUTU(u32);
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
		} else if (ic1 == SS2) { /* JIS X 0201 Kana; 2bytes */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISCS2(ic2)) { /* 2nd byte check passed */
				index = (ic2 - 0xa1);
				u32 = kiconv_ja_jisx0201kana_to_ucs2[index];
				KICONV_JA_PUTU(u32);
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
		} else if (ic1 == SS3) { /* JIS X 0212 or UDC; 3 bytes */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISCS3(ic2)) { /* 2nd byte check passed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_NGET_REP_FR_MB(ic3);
				} else {
					KICONV_JA_NGET(ic3);
				}
				if (KICONV_JA_ISCS3(ic3)) {
					/* 3rd byte check passed */
					ic2 &= KICONV_JA_CMASK;
					ic3 &= KICONV_JA_CMASK;
					KICONV_JA_CNV_JIS0212MS_TO_U2(id, u32,
					    ic2, ic3);
					if (u32 == KICONV_JA_NODEST) {
						index = ((ic2 - 0x21) * 94 +
						    (ic3 - 0x21));
						u32 = kiconv_ja_jisx0212_to_ucs2
						    [index];
					}
					if (u32 == KICONV_JA_REPLACE)
						rv++;
					KICONV_JA_PUTU(u32);
				} else { /* 3rd byte check failed */
					if (flag & KICONV_REPLACE_INVALID) {
						KICONV_JA_PUTU(
						    KICONV_JA_REPLACE);
						rv++;
					} else {
						KICONV_JA_RETERROR(EILSEQ)
					}
				}
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
		} else if (KICONV_JA_ISC1CTRLEUC(ic1)) {
			/* C1 control; 1 byte */
			u32 = ic1;
			KICONV_JA_PUTU(u32);
		} else { /* 1st byte check failed */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_PUTU(KICONV_JA_REPLACE);
				rv++;
			} else {
				KICONV_JA_RETERROR(EILSEQ)
			}
		}

next:
		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbytesleft = ileft;
		*outbytesleft = oleft;
	}

ret:
	return (rv);
}

static size_t
_do_kiconvstr_to_eucjp(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno, uint8_t id)
{
	uchar_t		ic;
	size_t		rv = 0;
	uint_t		ucs4;
	ushort_t	euc16;

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;
	size_t		read_len;

	boolean_t do_not_ignore_null;

	if ((inbuf == NULL) || (*inbuf == '\0')) {
		return (0);
	}

	ip = (uchar_t *)inbuf;
	ileft = *inbytesleft;
	op = outbuf;
	oleft = *outbytesleft;

	KICONV_JA_CHECK_UTF8_BOM_WITHOUT_STATE(ip, ileft);

	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ileft != 0) {
		KICONV_JA_GETU(&ucs4, flag);

		if (ucs4 == 0x0 && do_not_ignore_null) {
			return (0);
		}

		if (ucs4 > 0xffff) {
			/* non-BMP */
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		KICONV_JA_CNV_U2_TO_EUCJPMS(id, euc16, ucs4);
		if (euc16 == KICONV_JA_NODEST) {
			euc16 = kiconv_ja_ucs2_to_euc16((ushort_t)ucs4);
		}
		if (euc16 == KICONV_JA_NODEST) {
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		switch (euc16 & 0x8080) {
		case 0x0000:	/* CS0 */
			ic = (uchar_t)euc16;
			KICONV_JA_NPUT(ic);
			break;
		case 0x8080:	/* CS1 */
			ic = (uchar_t)((euc16 >> 8) & 0xff);
			KICONV_JA_NPUT(ic);
			ic = (uchar_t)(euc16 & 0xff);
			KICONV_JA_NPUT(ic);
			break;
		case 0x0080:	/* CS2 */
			KICONV_JA_NPUT(SS2);
			ic = (uchar_t)euc16;
			KICONV_JA_NPUT(ic);
			break;
		case 0x8000:	/* CS3 */
			KICONV_JA_NPUT(SS3);
			ic = (uchar_t)((euc16 >> 8) & 0xff);
			KICONV_JA_NPUT(ic);
			ic = (uchar_t)(euc16 & KICONV_JA_CMASK);
			KICONV_JA_NPUT(ic | KICONV_JA_CMSB);
			break;
		}
next:
		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbytesleft = ileft;
		*outbytesleft = oleft;
	}

ret:
	return (rv);
}

static size_t
kiconv_fr_eucjp(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	if (! kcd || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	return (_do_kiconv_fr_eucjp(kcd, inbuf, inbytesleft,
	    outbuf, outbytesleft, errno));
}

static size_t
kiconv_to_eucjp(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	if (! kcd || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	return (_do_kiconv_to_eucjp(kcd, inbuf, inbytesleft,
	    outbuf, outbytesleft, errno));
}

static size_t
kiconvstr_fr_eucjp(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_fr_eucjp(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_EUCJP));
}

static size_t
kiconvstr_to_eucjp(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_to_eucjp(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_EUCJP));
}

static size_t
kiconvstr_fr_eucjpms(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_fr_eucjp(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_EUCJP_MS));
}

static size_t
kiconvstr_to_eucjpms(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_to_eucjp(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_EUCJP_MS));
}

static size_t
_do_kiconv_fr_sjis(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uint_t	uni;			/* UTF-32 */
	uint_t	index;			/* index for table lookup */
	uchar_t	ic1, ic2;		/* 1st and 2nd bytes of a char */
	size_t	rv = 0;			/* return value of this function */

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;
	size_t		id = ((kiconv_state_t)kcd)->id;

	if ((inbuf == NULL) || (*inbuf == NULL)) {
		return (0);
	}

	ip = (uchar_t *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	while (ileft != 0) {
		KICONV_JA_NGET(ic1);			/* get 1st byte */

		if (KICONV_JA_ISASC((int)ic1)) {	/* ASCII; 1 byte */
			uni = kiconv_ja_jisx0201roman_to_ucs2[ic1];
			KICONV_JA_PUTU(uni);
		} else if (KICONV_JA_ISSJKANA(ic1)) { /* 0201 Kana; 1byte */
			uni = kiconv_ja_jisx0201kana_to_ucs2[(ic1 - 0xa1)];
			KICONV_JA_PUTU(uni);
		} else if (KICONV_JA_ISSJKANJI1(ic1)) { /* 0208/UDC; 2bytes */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				ic1 = kiconv_ja_sjtojis1[(ic1 - 0x80)];
				if (ic2 >= 0x9f) {
					ic1++;
				}
				ic2 = kiconv_ja_sjtojis2[ic2];
				KICONV_JA_CNV_JISMS_TO_U2(id, uni, ic1, ic2);
				if (uni == KICONV_JA_NODEST) {
					index = ((ic1 - 0x21) * 94)
					    + (ic2 - 0x21);
					uni = kiconv_ja_jisx0208_to_ucs2[index];
				}
				if (uni == KICONV_JA_REPLACE)
					rv++;
				KICONV_JA_PUTU(uni);
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
				/* NOTREACHED */
			}
		} else if (KICONV_JA_ISSJSUPKANJI1(ic1)) { /* VDC, 2 bytes */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				ic1 = kiconv_ja_sjtojis1[(ic1 - 0x80)];
				if (ic2 >= 0x9f) {
					ic1++;
				}
				index = ((ic1 - 0x21) * 94)
				    + (kiconv_ja_sjtojis2[ic2] - 0x21);
				uni = kiconv_ja_jisx0212_to_ucs2[index];
				if (uni == KICONV_JA_REPLACE)
					rv++;
				KICONV_JA_PUTU(uni);
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
			}
		} else if (KICONV_JA_ISSJIBM(ic1) || /* Extended IBM area */
		    KICONV_JA_ISSJNECIBM(ic1)) { /* NEC/IBM area */
			/*
			 * We need a special treatment for each codes.
			 * By adding some offset number for them, we
			 * can process them as the same way of that of
			 * extended IBM chars.
			 */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				ushort_t dest, upper, lower;
				dest = (ic1 << 8) + ic2;
				if ((0xed40 <= dest) && (dest <= 0xeffc)) {
					KICONV_JA_REMAP_NEC(dest);
					if (dest == 0xffff) {
						KICONV_JA_RETERROR(EILSEQ)
					}
				}
				/*
				 * XXX: 0xfa54 and 0xfa5b must be mapped
				 *	to JIS0208 area. Therefore we
				 *	have to do special treatment.
				 */
				if ((dest == 0xfa54) || (dest == 0xfa5b)) {
					if (dest == 0xfa54) {
						upper = 0x22;
						lower = 0x4c;
					} else {
						upper = 0x22;
						lower = 0x68;
					}
					KICONV_JA_CNV_JISMS_TO_U2(id, uni,
					    upper, lower);
					if (uni == KICONV_JA_NODEST) {
						index = (uint_t)((upper - 0x21)
						    * 94 + (lower - 0x21));
						uni = kiconv_ja_jisx0208_to_ucs2
						    [index];
					}
					if (uni == KICONV_JA_REPLACE)
						rv++;
					KICONV_JA_PUTU(uni);
				} else {
					dest = dest - 0xfa40 -
					    (((dest>>8) - 0xfa) * 0x40);
					dest = kiconv_ja_sjtoibmext[dest];
					if (dest == 0xffff) {
						KICONV_JA_RETERROR(EILSEQ)
					}
					upper = (dest >> 8) & KICONV_JA_CMASK;
					lower = dest & KICONV_JA_CMASK;
					KICONV_JA_CNV_JIS0212MS_TO_U2(id, uni,
					    upper, lower);
					if (uni == KICONV_JA_NODEST) {
						index = (uint_t)((upper - 0x21)
						    * 94 + (lower - 0x21));
						uni = kiconv_ja_jisx0212_to_ucs2
						    [index];
					}
					if (uni == KICONV_JA_REPLACE)
						rv++;
					KICONV_JA_PUTU(uni);
				}
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
			}
		} else if ((0xeb <= ic1) && (ic1 <= 0xec)) {
		/*
		 * Based on the draft convention of OSF-JVC CDEWG,
		 * characters in this area will be mapped to
		 * "CHIKAN-MOJI." (convertible character)
		 * We use U+FFFD in this case.
		 */
			KICONV_JA_NGET(ic2);
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				uni = 0xfffd;
				KICONV_JA_PUTU(uni);
			} else { /* 2nd byte check failed */
				KICONV_JA_RETERROR(EILSEQ)
			}
		} else { /* 1st byte check failed */
			KICONV_JA_RETERROR(EILSEQ)
		}

		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbuf = (char *)ip;
		*inbytesleft = ileft;
		*outbuf = op;
		*outbytesleft = oleft;
	}

ret:
	return (rv);
}

/*
 * _kiconv_ja_lookuptbl()
 * Return the index number if its index-ed number
 * is the same as dest value.
 */
static ushort_t
_kiconv_ja_lookuptbl(ushort_t dest)
{
	ushort_t tmp;
	int i;
	int sz = (sizeof (kiconv_ja_sjtoibmext) /
	    sizeof (kiconv_ja_sjtoibmext[0]));

	for (i = 0; i < sz; i++) {
		tmp = (kiconv_ja_sjtoibmext[i] & 0x7f7f);
		if (tmp == dest)
			return ((i + 0xfa40 + ((i / 0xc0) * 0x40)));
	}
	return (0x3f);
}

static size_t
_do_kiconv_to_sjis(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	uchar_t	ic;
	size_t		rv = 0;
	uint_t		ucs4;
	ushort_t	euc16;
	ushort_t	dest;

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;
	size_t		read_len;

	size_t		id = ((kiconv_state_t)kcd)->id;

	if ((inbuf == NULL) || (*inbuf == NULL)) {
		return (0);
	}

	ip = (uchar_t *)*inbuf;
	ileft = *inbytesleft;
	op = *outbuf;
	oleft = *outbytesleft;

	KICONV_JA_CHECK_UTF8_BOM(ip, ileft);

	while (ileft != 0) {
		KICONV_JA_GETU(&ucs4, 0);

		if (ucs4 > 0xffff) {
			/* non-BMP */
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		KICONV_JA_CNV_U2_TO_EUCJPMS(id, euc16, ucs4);
		if (euc16 == KICONV_JA_NODEST) {
			euc16 = kiconv_ja_ucs2_to_euc16((ushort_t)ucs4);
		}
		if (euc16 == KICONV_JA_NODEST) {
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		switch (euc16 & 0x8080) {
		case 0x0000:	/* CS0 */
			if (KICONV_JA_ISC1CTRL((uchar_t)euc16)) {
				KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
				rv++;
			} else {
				ic = (uchar_t)euc16;
				KICONV_JA_NPUT(ic);
			}
			break;
		case 0x8080:	/* CS1 */
			ic = (ushort_t)((euc16 >> 8) & KICONV_JA_CMASK);
			KICONV_JA_NPUT(kiconv_ja_jis208tosj1[ic]);
			/*
			 * for even number row (Ku), add 0x80 to
			 * look latter half of kiconv_ja_jistosj2[] array
			 */
			ic = (uchar_t)((euc16 & KICONV_JA_CMASK)
			    + (((ic % 2) == 0) ? 0x80 : 0x00));
			KICONV_JA_NPUT(kiconv_ja_jistosj2[ic]);
			break;
		case 0x0080:	/* CS2 */
			ic = (uchar_t)euc16;
			KICONV_JA_NPUT(ic);
			break;
		case 0x8000:	/* CS3 */
			ic = (ushort_t)((euc16 >> 8) & KICONV_JA_CMASK);
			if (euc16 == 0xa271) {
				/* NUMERO SIGN */
				KICONV_JA_NPUT(0x87);
				KICONV_JA_NPUT(0x82);
			} else if (ic < 0x75) { /* check if IBM VDC */
				dest = _kiconv_ja_lookuptbl(euc16 & 0x7f7f);
				if (dest == 0xffff) {
					KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
				} else {
					/* avoid putting NUL ('\0') */
					if (dest > 0xff) {
						KICONV_JA_NPUT(
						    (dest >> 8) & 0xff);
						KICONV_JA_NPUT(dest & 0xff);
					} else {
						KICONV_JA_NPUT(dest & 0xff);
					}
				}
			} else {
				KICONV_JA_NPUT(kiconv_ja_jis212tosj1[ic]);
				/*
				 * for even number row (Ku), add 0x80 to
				 * look latter half of kiconv_ja_jistosj2[]
				 */
				ic = (ushort_t)((euc16 & KICONV_JA_CMASK)
				    + (((ic % 2) == 0) ? 0x80 : 0x00));
				KICONV_JA_NPUT(kiconv_ja_jistosj2[ic]);
			}
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
	}

ret:
	return (rv);
}

static size_t
_do_kiconvstr_fr_sjis(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno, uint8_t id)
{
	uint_t		uni;		/* UTF-32 */
	uint_t		index;		/* index for table lookup */
	uchar_t		ic1, ic2;	/* 1st and 2nd bytes of a char */
	size_t		rv = 0;		/* return value of this function */

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;

	boolean_t do_not_ignore_null;

	if ((inbuf == NULL) || (*inbuf == '\0')) {
		return (0);
	}

	ip = (uchar_t *)inbuf;
	ileft = *inbytesleft;
	op = outbuf;
	oleft = *outbytesleft;

	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ileft != 0) {
		KICONV_JA_NGET(ic1);			/* get 1st byte */

		if (KICONV_JA_ISASC((int)ic1)) {	/* ASCII; 1 byte */
			if (ic1 == '\0' && do_not_ignore_null) {
				return (0);
			}
			uni = kiconv_ja_jisx0201roman_to_ucs2[ic1];
			KICONV_JA_PUTU(uni);
		} else if (KICONV_JA_ISSJKANA(ic1)) {
			/* JIS X 0201 Kana; 1 byte */
			uni = kiconv_ja_jisx0201kana_to_ucs2[(ic1 - 0xa1)];
			KICONV_JA_PUTU(uni);
		} else if (KICONV_JA_ISSJKANJI1(ic1)) {
			/* JIS X 0208 or UDC; 2 bytes */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				ic1 = kiconv_ja_sjtojis1[(ic1 - 0x80)];
				if (ic2 >= 0x9f) {
					ic1++;
				}
				ic2 = kiconv_ja_sjtojis2[ic2];
				KICONV_JA_CNV_JISMS_TO_U2(id, uni, ic1, ic2);
				if (uni == KICONV_JA_NODEST) {
					index = ((ic1 - 0x21) * 94)
					    + (ic2 - 0x21);
					uni = kiconv_ja_jisx0208_to_ucs2[index];
				}
				if (uni == KICONV_JA_REPLACE)
					rv++;
				KICONV_JA_PUTU(uni);
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
				/* NOTREACHED */
			}
		} else if (KICONV_JA_ISSJSUPKANJI1(ic1)) { /* VDC, 2 bytes */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				ic1 = kiconv_ja_sjtojis1[(ic1 - 0x80)];
				if (ic2 >= 0x9f) {
					ic1++;
				}
				index = ((ic1 - 0x21) * 94)
				    + (kiconv_ja_sjtojis2[ic2] - 0x21);
				uni = kiconv_ja_jisx0212_to_ucs2[index];
				if (uni == KICONV_JA_REPLACE)
					rv++;
				KICONV_JA_PUTU(uni);
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
		} else if (KICONV_JA_ISSJIBM(ic1) || /* Extended IBM area */
		    KICONV_JA_ISSJNECIBM(ic1)) { /* NEC/IBM area */
			/*
			 * We need a special treatment for each codes.
			 * By adding some offset number for them, we
			 * can process them as the same way of that of
			 * extended IBM chars.
			 */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				ushort_t dest, upper, lower;
				dest = (ic1 << 8) + ic2;
				if ((0xed40 <= dest) && (dest <= 0xeffc)) {
					KICONV_JA_REMAP_NEC(dest);
					if (dest == 0xffff) {
						if (flag &
						    KICONV_REPLACE_INVALID) {
							KICONV_JA_PUTU(
							    KICONV_JA_REPLACE);
							rv++;
						} else {
							KICONV_JA_RETERROR(
							    EILSEQ)
						}
					}
				}
				/*
				 * XXX: 0xfa54 and 0xfa5b must be mapped
				 *	to JIS0208 area. Therefore we
				 *	have to do special treatment.
				 */
				if ((dest == 0xfa54) || (dest == 0xfa5b)) {
					if (dest == 0xfa54) {
						upper = 0x22;
						lower = 0x4c;
					} else {
						upper = 0x22;
						lower = 0x68;
					}
					KICONV_JA_CNV_JISMS_TO_U2(id, uni,
					    upper, lower);
					if (uni == KICONV_JA_NODEST) {
						index = (uint_t)((upper - 0x21)
						    * 94 + (lower - 0x21));
						uni = kiconv_ja_jisx0208_to_ucs2
						    [index];
					}
					if (uni == KICONV_JA_REPLACE)
						rv++;
					KICONV_JA_PUTU(uni);
				} else {
					dest = dest - 0xfa40 -
					    (((dest>>8) - 0xfa) * 0x40);
					dest = kiconv_ja_sjtoibmext[dest];
					if (dest == 0xffff) {
						if (flag &
						    KICONV_REPLACE_INVALID) {
							KICONV_JA_PUTU(
							    KICONV_JA_REPLACE);
							rv++;
						} else {
							KICONV_JA_RETERROR(
							    EILSEQ)
						}
					}
					upper = (dest >> 8) & KICONV_JA_CMASK;
					lower = dest & KICONV_JA_CMASK;
					KICONV_JA_CNV_JIS0212MS_TO_U2(id, uni,
					    upper, lower);
					if (uni == KICONV_JA_NODEST) {
						index = (uint_t)((upper - 0x21)
						    * 94 + (lower - 0x21));
						uni = kiconv_ja_jisx0212_to_ucs2
						    [index];
					}
					if (uni == KICONV_JA_REPLACE)
						rv++;
					KICONV_JA_PUTU(uni);
				}
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
		} else if ((0xeb <= ic1) && (ic1 <= 0xec)) {
		/*
		 * Based on the draft convention of OSF-JVC CDEWG,
		 * characters in this area will be mapped to
		 * "CHIKAN-MOJI." (convertible character)
		 * We use U+FFFD in this case.
		 */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_NGET_REP_FR_MB(ic2);
			} else {
				KICONV_JA_NGET(ic2);
			}
			if (KICONV_JA_ISSJKANJI2(ic2)) {
				uni = 0xfffd;
				KICONV_JA_PUTU(uni);
			} else { /* 2nd byte check failed */
				if (flag & KICONV_REPLACE_INVALID) {
					KICONV_JA_PUTU(KICONV_JA_REPLACE);
					rv++;
				} else {
					KICONV_JA_RETERROR(EILSEQ)
				}
			}
		} else { /* 1st byte check failed */
			if (flag & KICONV_REPLACE_INVALID) {
				KICONV_JA_PUTU(KICONV_JA_REPLACE);
				rv++;
			} else {
				KICONV_JA_RETERROR(EILSEQ)
			}
		}

next:
		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbytesleft = ileft;
		*outbytesleft = oleft;
	}

ret:
	return (rv);
}

static size_t
_do_kiconvstr_to_sjis(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno, uint8_t id)
{
	uchar_t		ic;
	size_t		rv = 0;
	uint_t		ucs4;
	ushort_t	euc16;
	ushort_t	dest;

	uchar_t	*ip;
	size_t		ileft;
	char		*op;
	size_t		oleft;
	size_t		read_len;

	boolean_t do_not_ignore_null;

	if ((inbuf == NULL) || (*inbuf == '\0')) {
		return (0);
	}

	ip = (uchar_t *)inbuf;
	ileft = *inbytesleft;
	op = outbuf;
	oleft = *outbytesleft;

	KICONV_JA_CHECK_UTF8_BOM_WITHOUT_STATE(ip, ileft);

	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ileft != 0) {
		KICONV_JA_GETU(&ucs4, flag);

		if (ucs4 == 0x0 && do_not_ignore_null) {
			return (0);
		}

		if (ucs4 > 0xffff) {
			/* non-BMP */
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		KICONV_JA_CNV_U2_TO_EUCJPMS(id, euc16, ucs4);
		if (euc16 == KICONV_JA_NODEST) {
			euc16 = kiconv_ja_ucs2_to_euc16((ushort_t)ucs4);
		}
		if (euc16 == KICONV_JA_NODEST) {
			KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
			rv++;
			goto next;
		}

		switch (euc16 & 0x8080) {
		case 0x0000:	/* CS0 */
			if (KICONV_JA_ISC1CTRL((uchar_t)euc16)) {
				KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
				rv++;
			} else {
				ic = (uchar_t)euc16;
				KICONV_JA_NPUT(ic);
			}
			break;
		case 0x8080:	/* CS1 */
			ic = (ushort_t)((euc16 >> 8) & KICONV_JA_CMASK);
			KICONV_JA_NPUT(kiconv_ja_jis208tosj1[ic]);
			/*
			 * for even number row (Ku), add 0x80 to
			 * look latter half of kiconv_ja_jistosj2[] array
			 */
			ic = (uchar_t)((euc16 & KICONV_JA_CMASK)
			    + (((ic % 2) == 0) ? 0x80 : 0x00));
			KICONV_JA_NPUT(kiconv_ja_jistosj2[ic]);
			break;
		case 0x0080:	/* CS2 */
			ic = (uchar_t)euc16;
			KICONV_JA_NPUT(ic);
			break;
		case 0x8000:	/* CS3 */
			ic = (ushort_t)((euc16 >> 8) & KICONV_JA_CMASK);
			if (euc16 == 0xa271) {
				/* NUMERO SIGN */
				KICONV_JA_NPUT(0x87);
				KICONV_JA_NPUT(0x82);
			} else if (ic < 0x75) { /* check if IBM VDC */
				dest = _kiconv_ja_lookuptbl(euc16 & 0x7f7f);
				if (dest == 0xffff) {
					KICONV_JA_NPUT(KICONV_JA_DEF_SINGLE);
				} else {
					/* avoid putting NUL ('\0') */
					if (dest > 0xff) {
						KICONV_JA_NPUT(
						    (dest >> 8) & 0xff);
						KICONV_JA_NPUT(dest & 0xff);
					} else {
						KICONV_JA_NPUT(dest & 0xff);
					}
				}
			} else {
				KICONV_JA_NPUT(kiconv_ja_jis212tosj1[ic]);
				/*
				 * for even number row (Ku), add 0x80 to
				 * look latter half of kiconv_ja_jistosj2[]
				 */
				ic = (ushort_t)((euc16 & KICONV_JA_CMASK)
				    + (((ic % 2) == 0) ? 0x80 : 0x00));
				KICONV_JA_NPUT(kiconv_ja_jistosj2[ic]);
			}
			break;
		}

next:
		/*
		 * One character successfully converted so update
		 * values outside of this function's stack.
		 */
		*inbytesleft = ileft;
		*outbytesleft = oleft;
	}

ret:
	return (rv);
}

static size_t
kiconv_fr_sjis(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	if (! kcd || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	return (_do_kiconv_fr_sjis(kcd, inbuf, inbytesleft,
	    outbuf, outbytesleft, errno));
}

static size_t
kiconv_to_sjis(void *kcd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft, int *errno)
{
	if (! kcd || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	return (_do_kiconv_to_sjis(kcd, inbuf, inbytesleft,
	    outbuf, outbytesleft, errno));
}

static size_t
kiconvstr_fr_sjis(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_fr_sjis(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_SJIS));
}

static size_t
kiconvstr_to_sjis(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_to_sjis(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_SJIS));
}

static size_t
kiconvstr_fr_cp932(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_fr_sjis(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_CP932));
}

static size_t
kiconvstr_to_cp932(char *inbuf, size_t *inbytesleft, char *outbuf,
    size_t *outbytesleft, int flag, int *errno)
{
	return (_do_kiconvstr_to_sjis(inbuf, inbytesleft, outbuf,
	    outbytesleft, flag, errno, KICONV_JA_TBLID_CP932));
}

static kiconv_ops_t kiconv_ja_ops_tbl[] = {
	{
		"eucjp", "utf-8", open_eucjp,
		kiconv_to_eucjp, close_ja, kiconvstr_to_eucjp
	},
	{
		"utf-8", "eucjp", open_eucjp,
		kiconv_fr_eucjp, close_ja, kiconvstr_fr_eucjp
	},
	{
		"eucjpms", "utf-8", open_eucjpms,
		kiconv_to_eucjp, close_ja, kiconvstr_to_eucjpms
	},
	{
		"utf-8", "eucjpms", open_eucjpms,
		kiconv_fr_eucjp, close_ja, kiconvstr_fr_eucjpms
	},
	{
		"sjis", "utf-8", open_sjis,
		kiconv_to_sjis, close_ja, kiconvstr_to_sjis
	},
	{
		"utf-8", "sjis", open_sjis,
		kiconv_fr_sjis, close_ja, kiconvstr_fr_sjis
	},
	{
		"cp932", "utf-8", open_cp932,
		kiconv_to_sjis, close_ja, kiconvstr_to_cp932
	},
	{
		"utf-8", "cp932", open_cp932,
		kiconv_fr_sjis, close_ja, kiconvstr_fr_cp932
	}
};

static char *kiconv_ja_aliases[] = {"932", "shiftjis", "pck"};
static char *kiconv_ja_canonicals[] = {"cp932", "sjis", "sjis"};

#define	KICONV_JA_MAX_JA_OPS \
	(sizeof (kiconv_ja_ops_tbl) / sizeof (kiconv_ops_t))
#define	KICONV_JA_MAX_JA_ALIAS \
	(sizeof (kiconv_ja_aliases) / sizeof (char *))

static kiconv_module_info_t kiconv_ja_info = {
	"kiconv_ja",		/* module name */
	KICONV_JA_MAX_JA_OPS,	/* number of conversion in kiconv_ja */
	kiconv_ja_ops_tbl,	/* kiconv_ja ops table */
	KICONV_JA_MAX_JA_ALIAS,	/* number of alias in kiconv_ja */
	kiconv_ja_aliases,	/* kiconv_ja aliases */
	kiconv_ja_canonicals,	/* kiconv_ja canonicals */
	0
};

static struct modlkiconv modlkiconv_ja = {
	&mod_kiconvops,
	"kiconv module for Japanese",
	&kiconv_ja_info
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlkiconv_ja,
	NULL
};

int
_init(void)
{
	int err;

	err = mod_install(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_ja: failed to load kernel module");

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	/*
	 * If this module is being used, then, we cannot remove the module.
	 * The following checking will catch pretty much all usual cases.
	 *
	 * Any remaining will be catached by the kiconv_unregister_module()
	 * during mod_remove() at below.
	 */
	if (kiconv_module_ref_count(KICONV_MODULE_ID_JA))
		return (EBUSY);

	err = mod_remove(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_ja: failed to remove kernel module");

	return (err);
}
