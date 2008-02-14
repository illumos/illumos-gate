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
#include <sys/modctl.h>
#include <sys/u8_textprep.h>
#include <sys/kiconv.h>
#include <sys/kiconv_cck_common.h>
#include <sys/kiconv_ko.h>
#include <sys/kiconv_uhc_utf8.h>
#include <sys/kiconv_utf8_uhc.h>
#include <sys/kiconv_euckr_utf8.h>
#include <sys/kiconv_utf8_euckr.h>

static int8_t utf8_to_euckr(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static int8_t utf8_to_uhc(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val);
static int8_t ko_to_utf8(uint32_t ko_val, uchar_t *ob, uchar_t *obtail,
	size_t *ret_val, kiconv_table_array_t *table, size_t nitems);


#define	KICONV_KO_EUCKR		(0x01)
#define	KICONV_KO_UHC		(0x02)
#define	KICONV_KO_MAX_MAGIC_ID	(0x02)

static void *
open_fr_euckr()
{
	return ((void *)KICONV_KO_EUCKR);
}

static void *
open_fr_uhc()
{
	return ((void *)KICONV_KO_UHC);
}

static int
close_fr_ko(void *s)
{
	if ((uintptr_t)s > KICONV_KO_MAX_MAGIC_ID)
		return (EBADF);

	return (0);
}

/*
 * Encoding convertor from EUC-KR to UTF-8.
 */
static size_t
kiconv_fr_euckr(void *kcd, char **inbuf, size_t *inbufleft,
	char **outbuf, size_t *outbufleft, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	euckr_val;

	/* Check on the kiconv code conversion descriptor. */
	if (kcd == NULL || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* If this is a state reset request, process and return. */
	if (inbuf == NULL || *inbuf == NULL) {
		return (0);
	}

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		/*
		 * Issue EILSEQ error if the first byte is not a
		 * valid EUC-KR leading byte.
		 */
		if (! KICONV_KO_IS_EUCKR_BYTE(*ib)) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/*
		 * Issue EINVAL error if input buffer has an incomplete
		 * character at the end of the buffer.
		 */
		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		/*
		 * Issue EILSEQ error if the remaining byte is not
		 * a valid EUC-KR byte.
		 */
		if (! KICONV_KO_IS_EUCKR_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		euckr_val = (uint32_t)(*ib) << 8 | *(ib + 1);
		sz = ko_to_utf8(euckr_val, ob, obtail, &ret_val,
		    kiconv_euckr_utf8, KICONV_EUCKR_UTF8_MAX);

		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += 2;
		ob += sz;
	}

	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return (ret_val);
}

/*
 * String based encoding convertor from EUC-KR to UTF-8.
 */
static size_t
kiconvstr_fr_euckr(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	euckr_val;
	boolean_t	do_not_ignore_null;

	ret_val = 0;
	ib = (uchar_t *)inarray;
	ob = (uchar_t *)outarray;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ib < ibtail) {
		if (*ib == '\0' && do_not_ignore_null)
			break;

		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		oldib = ib;

		if (! KICONV_KO_IS_EUCKR_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EINVAL);
		}

		if (! KICONV_KO_IS_EUCKR_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_WITH_FLAG(2, EILSEQ);
		}

		euckr_val = *ib++;
		euckr_val = (euckr_val << 8) | *ib++;
		sz = ko_to_utf8(euckr_val, ob, obtail, &ret_val,
		    kiconv_euckr_utf8, KICONV_EUCKR_UTF8_MAX);

		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
		continue;

REPLACE_INVALID:
		if (obtail - ob < KICONV_UTF8_REPLACEMENT_CHAR_LEN) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR1;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR2;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR3;
		ret_val++;
	}

	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * Encoding convertor from Unified Hangul Code to UTF-8.
 */
static size_t
kiconv_fr_uhc(void *kcd, char **inbuf, size_t *inbufleft,
	char **outbuf, size_t *outbufleft, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	uhc_val;

	/* Check on the kiconv code conversion descriptor. */
	if (kcd == NULL || kcd == (void *)-1) {
		*errno = EBADF;
		return ((size_t)-1);
	}

	/* If this is a state reset request, process and return. */
	if (inbuf == NULL || *inbuf == NULL) {
		return (0);
	}

	ret_val = 0;
	ib = (uchar_t *)*inbuf;
	ob = (uchar_t *)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail) {
		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		/*
		 * Issue EILSEQ error if the first byte is not a
		 * valid UHC leading byte.
		 */
		if (! KICONV_KO_IS_UHC_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		/*
		 * Issue EINVAL error if input buffer has an incomplete
		 * character at the end of the buffer.
		 */
		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_AND_BREAK(EINVAL);
		}

		/*
		 * Issue EILSEQ error if the remaining byte is not
		 * a valid UHC byte.
		 */
		if (! KICONV_KO_IS_UHC_2nd_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_AND_BREAK(EILSEQ);
		}

		uhc_val = (uint32_t)(*ib) << 8 | *(ib + 1);
		sz = ko_to_utf8(uhc_val, ob, obtail, &ret_val,
		    kiconv_uhc_utf8, KICONV_UHC_UTF8_MAX);

		if (sz < 0) {
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ib += 2;
		ob += sz;
	}

	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return (ret_val);
}

/*
 * String based encoding convertor from Unified Hangul Code to UTF-8.
 */
static size_t
kiconvstr_fr_uhc(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	uchar_t		*ib;
	uchar_t		*ob;
	uchar_t		*ibtail;
	uchar_t		*obtail;
	uchar_t		*oldib;
	size_t		ret_val;
	int8_t		sz;
	uint32_t	uhc_val;
	boolean_t	do_not_ignore_null;

	ret_val = 0;
	ib = (uchar_t *)inarray;
	ob = (uchar_t *)outarray;
	ibtail = ib + *inlen;
	obtail = ob + *outlen;
	do_not_ignore_null = ((flag & KICONV_IGNORE_NULL) == 0);

	while (ib < ibtail) {
		if (*ib == '\0' && do_not_ignore_null)
			break;

		if (KICONV_IS_ASCII(*ib)) {
			if (ob >= obtail) {
				KICONV_SET_ERRNO_AND_BREAK(E2BIG);
			}

			*ob++ = *ib++;
			continue;
		}

		oldib = ib;

		if (! KICONV_KO_IS_UHC_1st_BYTE(*ib)) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EILSEQ);
		}

		if (ibtail - ib < 2) {
			KICONV_SET_ERRNO_WITH_FLAG(1, EINVAL);
		}

		if (! KICONV_KO_IS_UHC_2nd_BYTE(*(ib + 1))) {
			KICONV_SET_ERRNO_WITH_FLAG(2, EILSEQ);
		}

		uhc_val = *ib++;
		uhc_val = (uhc_val << 8) | *ib++;
		sz = ko_to_utf8(uhc_val, ob, obtail, &ret_val,
		    kiconv_uhc_utf8, KICONV_UHC_UTF8_MAX);

		if (sz < 0) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		ob += sz;
		continue;

REPLACE_INVALID:
		if (obtail - ob < KICONV_UTF8_REPLACEMENT_CHAR_LEN) {
			ib = oldib;
			KICONV_SET_ERRNO_AND_BREAK(E2BIG);
		}

		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR1;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR2;
		*ob++ = KICONV_UTF8_REPLACEMENT_CHAR3;
		ret_val++;
	}

	*inlen = ibtail - ib;
	*outlen = obtail - ob;

	return (ret_val);
}

/*
 * Encoding convertor from UTF-8 to EUC-KR.
 */
static size_t
kiconv_to_euckr(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	return (kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_euckr));
}

/*
 * Encoding convertor from UTF-8 to Unified Hangul Code.
 */
static size_t
kiconv_to_uhc(void *kcd, char **inbuf, size_t *inbytesleft,
	char **outbuf, size_t *outbytesleft, int *errno)
{
	return (kiconv_utf8_to_cck(kcd, inbuf, inbytesleft, outbuf,
	    outbytesleft, errno, utf8_to_uhc));
}

/*
 * String based encoding convertor from UTF-8 to EUC-KR.
 */
static size_t
kiconvstr_to_euckr(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_euckr);
}

/*
 * String based encoding convertor from UTF-8 to Unified Hangul Code.
 */
static size_t
kiconvstr_to_uhc(char *inarray, size_t *inlen, char *outarray,
	size_t *outlen, int flag, int *errno)
{
	return kiconvstr_utf8_to_cck((uchar_t *)inarray, inlen,
	    (uchar_t *)outarray, outlen, flag, errno, utf8_to_uhc);
}

/*
 * Convert an UTF-8 character to a character of ko encodings
 * (EUC-KR or UHC).
 */
static int8_t
utf8_to_ko(uint32_t utf8, uchar_t *ob, uchar_t *obtail, size_t *ret_val,
	kiconv_table_t *table, size_t nitems)
{
	size_t	index;
	size_t	kocode;
	int8_t  kolen;

	if (KICONV_KO_IS_UDC_IN_UTF8(utf8)) {
		/* User Definable Area handing. */
		kocode = (((utf8 & 0xF0000) >> 4) | ((utf8 & 0x3F00) >> 2) |
		    (utf8 & 0x3F)) - KICONV_KO_UDA_UCS4_START;
		if (kocode < KICONV_KO_UDA_RANGE) {
			kocode = (KICONV_KO_UDA_EUC_SEG1 << 8) |
			    (kocode + KICONV_KO_UDA_OFFSET_START);
		} else {
			/* 0x43 = 0xA1 - 0x5E */
			kocode = (KICONV_KO_UDA_EUC_SEG2 << 8) |
			    (kocode + 0x43);
		}

		index = 1;
	} else {
		index = kiconv_binsearch(utf8, table, nitems);
		kocode = table[index].value;
	}

	kolen = (kocode <= 0xFF) ? 1 : 2;

	if (obtail - ob < kolen) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;

	if (kolen > 1)
		*ob++ = (uchar_t)(kocode >> 8);
	*ob = (uchar_t)(kocode & 0xFF);

	return (kolen);
}

/*
 * Convert an UTF-8 character to Unified Hangual Code.
 */
/* ARGSUSED */
static int8_t
utf8_to_uhc(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	return (utf8_to_ko(utf8, ob, obtail, ret_val, kiconv_utf8_uhc,
	    KICONV_UTF8_UHC_MAX));
}

/*
 * Convert an UTF-8 character to EUC-KR.
 */
/* ARGSUSED */
static int8_t
utf8_to_euckr(uint32_t utf8, uchar_t **inbuf, uchar_t *ibtail,
	uchar_t *ob, uchar_t *obtail, size_t *ret_val)
{
	return (utf8_to_ko(utf8, ob, obtail, ret_val, kiconv_utf8_euckr,
	    KICONV_UTF8_EUCKR_MAX));
}

/*
 * Convert a single ko encoding (EUC-KR or UHC) character to UTF-8.
 */
static int8_t
ko_to_utf8(uint32_t ko_val, uchar_t *ob, uchar_t *obtail, size_t *ret_val,
	kiconv_table_array_t *table, size_t nitems)
{
	size_t	index;
	int8_t	sz;
	uchar_t	udc[3];
	uchar_t	*u8;

	if (KICONV_KO_IS_UDC_IN_EUC(ko_val)) {
		/* UDA(User Definable Area) handling. */
		uint32_t u32;

		u32 = (ko_val & 0xFF) + (((ko_val & 0xFF00) == 0xC900) ?
		    KICONV_KO_UDA_OFFSET_1 : KICONV_KO_UDA_OFFSET_2);
		udc[0] = 0xEF;
		udc[1] = (uchar_t)(0x80 | (u32 & 0x00000FC0) >> 6);
		udc[2] = (uchar_t)(0x80 | (u32 & 0x0000003F));
		u8 = udc;
		index = 1;
	} else {
		index = kiconv_binsearch(ko_val, table, nitems);
		u8 = table[index].u8;
	}

	sz = u8_number_of_bytes[u8[0]];

	if (obtail - ob < sz) {
		*ret_val = (size_t)-1;
		return (-1);
	}

	if (index == 0)
		(*ret_val)++;	/* Non-identical conversion */

	for (index = 0; index < sz; index++)
		*ob++ = u8[index];

	return (sz);
}

static kiconv_ops_t kiconv_ko_ops_tbl[] = {
	{
		"euc-kr", "utf-8", kiconv_open_to_cck, kiconv_to_euckr,
		kiconv_close_to_cck, kiconvstr_to_euckr
	},
	{
		"utf-8", "euc-kr", open_fr_euckr, kiconv_fr_euckr,
		close_fr_ko, kiconvstr_fr_euckr
	},
	{
		"unifiedhangul", "utf-8", kiconv_open_to_cck, kiconv_to_uhc,
		kiconv_close_to_cck, kiconvstr_to_uhc
	},
	{
		"utf-8", "unifiedhangul", open_fr_uhc, kiconv_fr_uhc,
		close_fr_ko, kiconvstr_fr_uhc
	}
};

static kiconv_module_info_t kiconv_ko_info = {
	"kiconv_ko",		/* module name */
	sizeof (kiconv_ko_ops_tbl) / sizeof (kiconv_ko_ops_tbl[0]),
	kiconv_ko_ops_tbl,
	0,
	NULL,
	NULL,
	0
};

static struct modlkiconv modlkiconv_ko = {
	&mod_kiconvops,
	"kiconv korean module 1.0",
	&kiconv_ko_info
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlkiconv_ko,
	NULL
};

int
_init(void)
{
	int err;

	err = mod_install(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_ko: failed to load kernel module");

	return (err);
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
	if (kiconv_module_ref_count(KICONV_MODULE_ID_KO))
		return (EBUSY);

	err = mod_remove(&modlinkage);
	if (err)
		cmn_err(CE_WARN, "kiconv_ko: failed to remove kernel module");

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
