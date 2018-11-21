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
 * COPYRIGHT AND PERMISSION NOTICE
 *
 * Copyright (c) 1991-2005 Unicode, Inc. All rights reserved. Distributed
 * under the Terms of Use in http://www.unicode.org/copyright.html.
 *
 * This file has been modified by Sun Microsystems, Inc.
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include	<sys/types.h>

#if	defined(JFP_ICONV_FROMCODE_UTF32BE)||defined(JFP_ICONV_FROMCODE_UTF32LE)
#define	JFP_ICONV_FROMCODE_UTF32
#endif

#if	defined(JFP_ICONV_FROMCODE_UTF16BE)||defined(JFP_ICONV_FROMCODE_UTF16LE)
#define	JFP_ICONV_FROMCODE_UTF16
#endif

#if	defined(JFP_ICONV_FROMCODE_UCS2BE)||defined(JFP_ICONV_FROMCODE_UCS2LE)
#define	JFP_ICONV_FROMCODE_UCS2
#endif

#if	defined(JFP_ICONV_TOCODE_UTF32BE)||defined(JFP_ICONV_TOCODE_UTF32LE)
#define	JFP_ICONV_TOCODE_UTF32
#endif

#if	defined(JFP_ICONV_TOCODE_UTF16BE)||defined(JFP_ICONV_TOCODE_UTF16LE)
#define	JFP_ICONV_TOCODE_UTF16
#endif

#if	defined(JFP_ICONV_TOCODE_UCS2BE)||defined(JFP_ICONV_TOCODE_UCS2LE)
#define	JFP_ICONV_TOCODE_UCS2
#endif


#define	BOM	0xfeff
#define	BSBOM16	0xfffe
#define	BSBOM32	0xfffe0000
#define	REPLACE	0xfffd
#define	IFHISUR(x)	((0xd800 <= (x)) && ((x) <= 0xdbff))
#define	IFLOSUR(x)	((0xdc00 <= (x)) && ((x) <= 0xdfff))

typedef struct {
	boolean_t         bom_written;
	boolean_t         little_endian;
} ucs_state_t;


#if	defined(JFP_ICONV_FROMCODE_UTF32)

static size_t				/* return #bytes read, or -1 */
read_unicode(
	unsigned int	*p,		/* point variable to store UTF-32 */
	unsigned char	**pip,		/* point pointer to input buf */
	size_t		*pileft,	/* point #bytes left in input buf */
	ucs_state_t	*state)		/* BOM state and endian */
{
	unsigned char	*ip = *pip;
	size_t		ileft = *pileft;
	size_t		rv = (size_t)0; /* return value */
	unsigned char	ic1, ic2, ic3, ic4;	/* bytes read */
	unsigned int	u32;		/* resulted UTF-32 */

	NGET(ic1, "UTF32-1");
	NGET(ic2, "UTF32-2");
	NGET(ic3, "UTF32-3");
	NGET(ic4, "UTF32-4");

	if (state->bom_written == B_FALSE) {
		u32 = 0U;
		u32 |= (unsigned int)ic1 << 24;
		u32 |= (unsigned int)ic2 << 16;
		u32 |= (unsigned int)ic3 << 8;
		u32 |= (unsigned int)ic4 << 0;
		if (u32 == BOM) {
			state->bom_written = B_TRUE;
			state->little_endian = B_FALSE;
			*p = BOM;
			rv = (size_t)0;
			goto ret;
		} else if (u32 == BSBOM32) {
			state->bom_written = B_TRUE;
			state->little_endian = B_TRUE;
			*p = BOM;
			rv = (size_t)0;
			goto ret;
		} else {
			state->bom_written = B_TRUE;
		}
	}

	if (state->little_endian == B_TRUE) {
		u32 = 0U;
		u32 |= (unsigned int)ic1 << 0;
		u32 |= (unsigned int)ic2 << 8;
		u32 |= (unsigned int)ic3 << 16;
		u32 |= (unsigned int)ic4 << 24;
	} else {
		u32 = 0U;
		u32 |= (unsigned int)ic1 << 24;
		u32 |= (unsigned int)ic2 << 16;
		u32 |= (unsigned int)ic3 << 8;
		u32 |= (unsigned int)ic4 << 0;
	}

	if (u32 == BSBOM32) {
		RETERROR(EILSEQ, "byte-swapped BOM detected")
	}

	if ((u32 == 0xfffe) || (u32 == 0xffff) || (u32 > 0x10ffff)
			|| IFHISUR(u32) || IFLOSUR(u32)) {
		RETERROR(EILSEQ, "illegal in UTF-32")
	}

	*p = u32;
	rv = *pileft - ileft;

ret:
	if (rv != (size_t)-1) {
		/* update *pip and *pileft only on successful return */
		*pip = ip;
		*pileft = ileft;
	}

	return (rv);
}

#elif	defined(JFP_ICONV_FROMCODE_UTF16) || defined(JFP_ICONV_FROMCODE_UCS2)

static size_t				/* return #bytes read, or -1 */
read_unicode(
	unsigned int	*p,		/* point variable to store UTF-32 */
	unsigned char	**pip,		/* point pointer to input buf */
	size_t		*pileft,	/* point #bytes left in input buf */
	ucs_state_t	*state)		/* BOM state and endian */
{
	unsigned char	*ip = *pip;
	size_t		ileft = *pileft;
	size_t		rv = (size_t)0; /* return value */
	unsigned char	ic1, ic2;	/* bytes read */
	unsigned int	u32;		/* resulted UTF-32 */
#ifndef	JFP_ICONV_FROMCODE_UCS2
	unsigned int	losur;		/* low surrogate */
#endif

	NGET(ic1, "UTF16-1");	/* read 1st byte */
	NGET(ic2, "UTF16-2");	/* read 2nd byte */

	if (state->bom_written == B_FALSE) {
		u32 = 0U;
		u32 |= (unsigned int)ic1 << 8;
		u32 |= (unsigned int)ic2 << 0;
		if (u32 == BOM) {
			state->bom_written = B_TRUE;
			state->little_endian = B_FALSE;
			*p = BOM;
			rv = (size_t)0;
			goto ret;
		} else if (u32 == BSBOM16) {
			state->bom_written = B_TRUE;
			state->little_endian = B_TRUE;
			*p = BOM;
			rv = (size_t)0;
			goto ret;
		} else {
			state->bom_written = B_TRUE;
		}
	}

	if (state->little_endian == B_TRUE) {
		u32 = (((unsigned int)ic2) << 8) | ic1;
	} else {
		u32 = (((unsigned int)ic1) << 8) | ic2;
	}

	if (u32 == BSBOM16) {
		RETERROR(EILSEQ, "byte-swapped BOM detected")
	}

	if ((u32 == 0xfffe) || (u32 == 0xffff) || (u32 > 0x10ffff)
			|| (IFLOSUR(u32))) {
		RETERROR(EILSEQ, "illegal in UTF16")
	}

	if (IFHISUR(u32)) {
#if	defined(JFP_ICONV_FROMCODE_UCS2)
		RETERROR(EILSEQ, "surrogate is illegal in UCS2")
#else	/* !defined(JFP_ICONV_FROMCODE_UCS2) */
		NGET(ic1, "LOSUR-1");
		NGET(ic2, "LOSUR-2");

		if (state->little_endian == B_TRUE) {
			losur = (((unsigned int)ic2) << 8) | ic1;
		} else {
			losur = (((unsigned int)ic1) << 8) | ic2;
		}

		if (IFLOSUR(losur)) {
			u32 = ((u32 - 0xd800) * 0x400)
				+ (losur - 0xdc00) + 0x10000;
		} else {
			RETERROR(EILSEQ, "low-surrogate expected")
		}
#endif	/* defined(JFP_ICONV_FROMCODE_UCS2) */
	}

	*p = u32;
	rv = *pileft - ileft;

ret:
	if (rv != (size_t)-1) {
		/* update *pip and *pileft only on successful return */
		*pip = ip;
		*pileft = ileft;
	}

	return (rv);
}

#else	/* JFP_ICONV_FROMCODE_UTF8 (default) */

/*
 * The following vector shows remaining bytes in a UTF-8 character.
 * Index will be the first byte of the character.
 */
static const char remaining_bytes_tbl[0x100] = {
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,

   /*  C0  C1  C2  C3  C4  C5  C6  C7  C8  C9  CA  CB  CC  CD  CE  CF  */
	0,  0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,

   /*  D0  D1  D2  D3  D4  D5  D6  D7  D8  D9  DA  DB  DC  DD  DE  DF  */
	1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,

   /*  E0  E1  E2  E3  E4  E5  E6  E7  E8  E9  EA  EB  EC  ED  EE  EF  */
	2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,

   /*  F0  F1  F2  F3  F4  F5  F6  F7  F8  F9  FA  FB  FC  FD  FE  FF  */
	3,  3,  3,  3,  3,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};


/*
 * The following is a vector of bit-masks to get used bits in
 * the first byte of a UTF-8 character.  Index is remaining bytes at above of
 * the character.
 */
static const char masks_tbl[6] = { 0x00, 0x1f, 0x0f, 0x07, 0x03, 0x01 };


/*
 * The following two vectors are to provide valid minimum and
 * maximum values for the 2'nd byte of a multibyte UTF-8 character for
 * better illegal sequence checking. The index value must be the value of
 * the first byte of the UTF-8 character.
 */
static const unsigned char valid_min_2nd_byte[0x100] = {
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
     /*  C0    C1    C2    C3    C4    C5    C6    C7  */
	0,    0,    0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
     /*  C8    C9    CA    CB    CC    CD    CE    CF  */
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
     /*  D0    D1    D2    D3    D4    D5    D6    D7  */
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
     /*  D8    D9    DA    DB    DC    DD    DE    DF  */
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
     /*  E0    E1    E2    E3    E4    E5    E6    E7  */
	0xa0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
     /*  E8    E9    EA    EB    EC    ED    EE    EF  */
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
     /*  F0    F1    F2    F3    F4    F5    F6    F7  */
	0x90, 0x80, 0x80, 0x80, 0x80, 0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
};

static const unsigned char valid_max_2nd_byte[0x100] = {
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
     /*  C0    C1    C2    C3    C4    C5    C6    C7  */
	0,    0,    0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf,
     /*  C8    C9    CA    CB    CC    CD    CE    CF  */
	0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf,
     /*  D0    D1    D2    D3    D4    D5    D6    D7  */
	0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf,
     /*  D8    D9    DA    DB    DC    DD    DE    DF  */
	0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf,
     /*  E0    E1    E2    E3    E4    E5    E6    E7  */
	0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf,
     /*  E8    E9    EA    EB    EC    ED    EE    EF  */
	0xbf, 0xbf, 0xbf, 0xbf, 0xbf, 0x9f, 0xbf, 0xbf,
     /*  F0    F1    F2    F3    F4    F5    F6    F7  */
	0xbf, 0xbf, 0xbf, 0xbf, 0x8f, 0,    0,    0,
	0,    0,    0,    0,    0,    0,    0,    0,
};

static size_t
utf8_ucs(unsigned int *p, unsigned char **pip, size_t *pileft)
{
	unsigned int	l;	/* to be copied to *p on successful return */
	unsigned char	ic;	/* current byte */
	unsigned char	ic1;	/* 1st byte */
	unsigned char	*ip = *pip;	/* next byte to read */
	size_t		ileft = *pileft; /* number of bytes available */
	size_t		rv = (size_t)0; /* return value of this function */
	int		remaining_bytes;

	NGET(ic, "no bytes available");	/* read 1st byte */
	ic1 = ic;
	l = ic1; /* get bits from 1st byte to UCS value */

	if (ic1 < 0x80) {
		/* successfully converted */
		*p = l;
		rv = *pileft - ileft;
		goto ret;
	}

	remaining_bytes = remaining_bytes_tbl[ic1];

	if (remaining_bytes != 0) {
		l &= masks_tbl[remaining_bytes];

		for (; remaining_bytes > 0; remaining_bytes--) {
			if (ic1 != 0U) {
				NGET(ic, "2nd byte of UTF-8");
				if ((ic < valid_min_2nd_byte[ic1]) ||
					(ic > valid_max_2nd_byte[ic1])) {
					RETERROR(EILSEQ, "2nd byte is invalid")
				}
				ic1 = 0U; /* 2nd byte check done */
			} else {
				NGET(ic, "3rd or later byte of UTF-8");
				if ((ic < 0x80) || (ic > 0xbf)) {
				RETERROR(EILSEQ, "3rd or later byte is invalid")
				}
			}
			l = (l << 6) | (ic & 0x3f);
		}

		/* successfully converted */
		*p = l;
		rv = *pileft - ileft;
		goto ret;
	} else {
		RETERROR(EILSEQ, "1st byte is invalid")
	}

ret:
	if (rv != (size_t)-1) {
		/*
		 * update *pip and *pileft on successful return
		 */
		*pip = ip;
		*pileft = ileft;
	}

	return (rv);
}

/* for UTF-8 */
static size_t				/* return #bytes read, or -1 */
read_unicode(
	unsigned int	*p,		/* point variable to store UTF-32 */
	unsigned char	**pip,		/* point pointer to input buf */
	size_t		*pileft,	/* point #bytes left in input buf */
	ucs_state_t	*state)		/* BOM state and endian - unused */
{
	return (utf8_ucs(p, pip, pileft));
}

#endif

#if	defined(JFP_ICONV_TOCODE_UTF32)

static size_t
write_unicode(
	unsigned int	u32,		/* UTF-32 to write */
	char		**pop,		/* point pointer to output buf */
	size_t		*poleft,	/* point #bytes left in output buf */
	ucs_state_t	*state,		/* BOM state and endian */
	const char	*msg)		/* debug message */
{
	char		*op = *pop;
	size_t		oleft = *poleft;
	size_t		rv = (size_t)0;		/* return value */
	unsigned char	ic1, ic2, ic3, ic4;	/* bytes to be written */

	if (state->bom_written == B_FALSE) {
		if (state->little_endian == B_TRUE) {
			ic1 = (unsigned char)((BOM >> 0) & 0xff);
			ic2 = (unsigned char)((BOM >> 8) & 0xff);
			ic3 = (unsigned char)((BOM >> 16) & 0xff);
			ic4 = (unsigned char)((BOM >> 24) & 0xff);
		} else {
			ic1 = (unsigned char)((BOM >> 24) & 0xff);
			ic2 = (unsigned char)((BOM >> 16) & 0xff);
			ic3 = (unsigned char)((BOM >> 8) & 0xff);
			ic4 = (unsigned char)((BOM >> 0) & 0xff);
		}
		rv += 4;
		NPUT(ic1, "BOM32-1")
		NPUT(ic2, "BOM32-2")
		NPUT(ic3, "BOM32-3")
		NPUT(ic4, "BOM32-4")
	}

	if (state->little_endian == B_TRUE) {
		ic1 = (unsigned char)((u32 >> 0) & 0xff);
		ic2 = (unsigned char)((u32 >> 8) & 0xff);
		ic3 = (unsigned char)((u32 >> 16) & 0xff);
		ic4 = (unsigned char)((u32 >> 24) & 0xff);
		rv += 4;
	} else {
		ic1 = (unsigned char)((u32 >> 24) & 0xff);
		ic2 = (unsigned char)((u32 >> 16) & 0xff);
		ic3 = (unsigned char)((u32 >> 8) & 0xff);
		ic4 = (unsigned char)((u32 >> 0) & 0xff);
		rv += 4;
	}

	NPUT(ic1, "UTF32-1")
	NPUT(ic2, "UTF32-2")
	NPUT(ic3, "UTF32-3")
	NPUT(ic4, "UTF32-4")

ret:
	if (rv != (size_t)-1) {
		/* update *pop and *poleft only on successful return */
		*pop = op;
		*poleft = oleft;
		if (state->bom_written == B_FALSE)
			state->bom_written = B_TRUE;
	}

	return (rv);
}

#elif	defined(JFP_ICONV_TOCODE_UTF16) || defined(JFP_ICONV_TOCODE_UCS2)

static size_t
write_unicode(
	unsigned int	u32,		/* UTF-32 to write */
	char		**pop,		/* point pointer to output buf */
	size_t		*poleft,	/* point #bytes left in output buf */
	ucs_state_t	*state,		/* BOM state and endian */
	const char	*msg)		/* debug message */
{
	char		*op = *pop;
	size_t		oleft = *poleft;
	size_t		rv = (size_t)0;	/* return value */
	unsigned char	ic1, ic2;	/* bytes to be written */
	unsigned int	losur = 0U;		/* Hi/Lo surrogates */

	if (state->bom_written == B_FALSE) {
		if (state->little_endian == B_TRUE) {
			ic1 = (unsigned char)((BOM >> 0) & 0xff);
			ic2 = (unsigned char)((BOM >> 8) & 0xff);
		} else {
			ic1 = (unsigned char)((BOM >> 8) & 0xff);
			ic2 = (unsigned char)((BOM >> 0) & 0xff);
		}
		rv += 2;
		NPUT(ic1, "BOM16-1")
		NPUT(ic2, "BOM16-2")
	}

	if (u32 > 0xffff) {
#if	defined(JFP_ICONV_TOCODE_UCS2)
		u32 = REPLACE;
#else	/* !defined(JFP_ICONV_TOCODE_UCS2) */
		losur = ((u32 - 0x10000) % 0x400) + 0xdc00;
		u32 = ((u32 - 0x10000) / 0x400) + 0xd800;
#endif	/* defined(JFP_ICONV_TOCODE_UCS2) */
	}

	if (state->little_endian == B_TRUE) {
		ic1 = (unsigned char)(u32 & 0xff);
		ic2 = (unsigned char)((u32 >> 8) & 0xff);
		rv += 2;
	} else {
		ic1 = (unsigned char)((u32 >> 8) & 0xff);
		ic2 = (unsigned char)(u32 & 0xff);
		rv += 2;
	}

	NPUT(ic1, "UTF16-1")
	NPUT(ic2, "UTF16-2")

	if (losur != 0U) {
		if (state->little_endian == B_TRUE) {
			ic1 = (unsigned char)(losur & 0xff);
			ic2 = (unsigned char)((losur >> 8) & 0xff);
			rv += 2;
		} else {
			ic1 = (unsigned char)((losur >> 8) & 0xff);
			ic2 = (unsigned char)(losur & 0xff);
			rv += 2;
		}

		NPUT(ic1, "LOSUR-1")
		NPUT(ic2, "LOSUR-2")
	}


ret:
	if (rv != (size_t)-1) {
		/* update *pop and *poleft only on successful return */
		*pop = op;
		*poleft = oleft;
		if (state->bom_written == B_FALSE)
			state->bom_written = B_TRUE;
	}

	return (rv);
}

#else	/* JFP_ICONV_TOCODE_UTF8 (default) */

static size_t
write_unicode(
	unsigned int	u32,		/* UTF-32 to write */
	char		**pop,		/* point pointer to output buf */
	size_t		*poleft,	/* point #bytes left in output buf */
	ucs_state_t	*state,		/* BOM state and endian - unused */
	const char	*msg)		/* debug message */
{
	char	*op = *pop;
	size_t	oleft = *poleft;
	size_t	rv = 0;			/* return value */

	if (u32 <= 0x7f) {
		NPUT((unsigned char)(u32), msg);
		rv = 1;
	} else if (u32 <= 0x7ff) {
		NPUT((unsigned char)((((u32)>>6) & 0x1f) | 0xc0), msg);
		NPUT((unsigned char)((((u32)>>0) & 0x3f) | 0x80), msg);
		rv = 2;
	} else if ((u32 >= 0xd800) && (u32 <= 0xdfff)) {
		RETERROR(EILSEQ, "surrogate in UTF-8")
	} else if (u32 <= 0xffff) {
		NPUT((unsigned char)((((u32)>>12) & 0x0f) | 0xe0), msg);
		NPUT((unsigned char)((((u32)>>6) & 0x3f) | 0x80), msg);
		NPUT((unsigned char)((((u32)>>0) & 0x3f) | 0x80), msg);
		rv = 3;
	} else if (u32 <= 0x10ffff) {
		NPUT((unsigned char)((((u32)>>18) & 0x07) | 0xf0), msg);
		NPUT((unsigned char)((((u32)>>12) & 0x3f) | 0x80), msg);
		NPUT((unsigned char)((((u32)>>6) & 0x3f) | 0x80), msg);
		NPUT((unsigned char)((((u32)>>0) & 0x3f) | 0x80), msg);
		rv = 4;
	} else {
		RETERROR(EILSEQ, "beyond range of UTF-8")
	}

ret:
	if (rv != (size_t)-1) {
		/* update *pop and *poleft only on successful return */
		*pop = op;
		*poleft = oleft;
	}

	return (rv);
}

#endif

#define	GETU(pu32) \
	switch (read_unicode(pu32, &ip, &ileft, (ucs_state_t *)cd)) { \
	case (size_t)-1: \
		/* errno has been set in read_unicode() */ \
		rv = (size_t)-1; \
		goto ret; \
	case (size_t)0: \
		/* character read was handled in the read_unicode() */ \
		/* no further evaluation needed in caller side */ \
		rv = (size_t)0; \
		goto next; \
	default: \
		break; \
	}


#define	PUTU(u32, msg)	\
	if (write_unicode(u32, &op, &oleft, (ucs_state_t *)cd, msg) \
			== (size_t)-1) { \
		rv = ((size_t)-1);\
		goto ret; \
	}

#include	<stdlib.h>

static void
_icv_reset_unicode(void *cd)
{
	ucs_state_t	*state = (ucs_state_t *)cd;

#if	defined(JFP_ICONV_FROMCODE_UTF32BE) || \
	defined(JFP_ICONV_TOCODE_UTF32BE) || \
	defined(JFP_ICONV_FROMCODE_UTF16BE) || \
	defined(JFP_ICONV_TOCODE_UTF16BE) || \
	defined(JFP_ICONV_FROMCODE_UCS2BE) || \
	defined(JFP_ICONV_TOCODE_UCS2BE)
	state->little_endian = B_FALSE;
	state->bom_written = B_TRUE;
#elif	defined(JFP_ICONV_FROMCODE_UTF32LE) || \
	defined(JFP_ICONV_TOCODE_UTF32LE) || \
	defined(JFP_ICONV_FROMCODE_UTF16LE) || \
	defined(JFP_ICONV_TOCODE_UTF16LE) || \
	defined(JFP_ICONV_FROMCODE_UCS2LE) || \
	defined(JFP_ICONV_TOCODE_UCS2LE)
	state->little_endian = B_TRUE;
	state->bom_written = B_TRUE;
#elif	defined(_LITTLE_ENDIAN)
	state->little_endian = B_TRUE;
	state->bom_written = B_FALSE;
#endif

	return;
}

static void *
_icv_open_unicode(size_t extsize)
{
	ucs_state_t	*cd;

	if ((cd = (ucs_state_t *)calloc(1,
			sizeof (ucs_state_t) + extsize)) == NULL) {
		errno = ENOMEM;
		return ((void *)-1);
	}

	_icv_reset_unicode((void *)cd);

	return ((void *)cd);
}

static void
_icv_close_unicode(void *cd)
{
	if (cd == NULL) {
		errno = EBADF;
	} else {
		free(cd);
	}
	return;
}

static void *
_icv_get_ext(void *cd)
{
	return ((void *)((unsigned char *)cd + sizeof (ucs_state_t)));
}
