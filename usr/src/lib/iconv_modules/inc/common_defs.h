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
 * Copyright 1998-1999, 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	COMMON_DEFS_H
#define	COMMON_DEFS_H

#include <sys/types.h>

/* Following are replacement characters for non-identical character cases. */

#define ICV_TYPE_NON_IDENTICAL_CHAR	(-1)
#define ICV_TYPE_ILLEGAL_CHAR		(-2)

#define	ICV_CHAR_ASCII_REPLACEMENT	('?')
#define	ICV_CHAR_UTF8_REPLACEMENT	(0x00efbfbd)
#define	ICV_CHAR_UCS2_REPLACEMENT	(0xfffd)

#define	IL_				ICV_TYPE_ILLEGAL_CHAR

typedef enum { false = 0, true = 1 } boolean;

static const char number_of_bytes_in_utf8_char[0x100] = {
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
	 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,

    /*  80  81  82  83  84  85  86  87  88  89  8A  8B  8C  8D  8E  8F  */
	IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,

    /*  90  91  92  93  94  95  96  97  98  99  9A  9B  9C  9D  9E  9F  */
	IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,

    /*  A0  A1  A2  A3  A4  A5  A6  A7  A8  A9  AA  AB  AC  AD  AE  AF  */
	IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,

    /*  B0  B1  B2  B3  B4  B5  B6  B7  B8  B9  BA  BB  BC  BD  BE  BF  */
	IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,IL_,

    /*  C0  C1  C2  C3  C4  C5  C6  C7  C8  C9  CA  CB  CC  CD  CE  CF  */
	IL_,IL_,2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,

    /*  D0  D1  D2  D3  D4  D5  D6  D7  D8  D9  DA  DB  DC  DD  DE  DF  */
	 2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,

    /*  E0  E1  E2  E3  E4  E5  E6  E7  E8  E9  EA  EB  EC  ED  EE  EF  */
	 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,

    /*  F0  F1  F2  F3  F4  F5  F6  F7  F8  F9  FA  FB  FC  FD  FE  FF  */
	 4,  4,  4,  4,  4,  IL_, IL_, IL_, IL_, IL_, IL_, IL_, IL_, IL_, IL_, IL_,
};

#undef IL_

/*
 * Following is a vector of bit-masks to get used bits in the first byte of
 * a UTF-8 character.  Index is the number of bytes in the UTF-8 character
 * and the index value comes from above table.
 */
static const char masks_tbl[7] = { 0x00, 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

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


/*
 * Following "6" and "0x3f" came from 10xx xxxx bit representation of UTF-8
 * characters' second to sixth bytes.
 */
#define	ICV_UTF8_BIT_SHIFT		6
#define	ICV_UTF8_BIT_MASK		0x3f
#define	ICV_FETCH_UTF8_BOM_SIZE		6

#define  ICV_FETCH_UCS4_SIZE     4
#if defined(UCS_2) || defined(UCS_2BE) || defined(UCS_2LE) || \
   defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
#define ICV_FETCH_UCS_SIZE              2
#define ICV_FETCH_UCS_SIZE_TWO          4
#elif defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE) || \
   defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
#define ICV_FETCH_UCS_SIZE              4
#define ICV_FETCH_UCS_SIZE_TWO          8
#endif


/*
 * UTF-8 represantations of critical values
 */
#define	ICV_UTF8_REPRESENTATION_d800		(0x00eda080UL)
#define	ICV_UTF8_REPRESENTATION_dfff		(0x00edbfbfUL)
#define	ICV_UTF8_REPRESENTATION_fffe		(0x00efbfbeUL)
#define	ICV_UTF8_REPRESENTATION_ffff		(0x00efbfbfUL)
#define	ICV_UTF8_REPRESENTATION_7fffffff	(0x00fdbfbfbfbfbfULL)

/*
 * common utility to convert utf8 string to unicode
 */
extern  int convert_utf8_to_ucs4(uchar_t *, int, unsigned int *);

extern  int is_valid_utf8_string(unsigned char *, int);

/* UCS-2/UCS-4/UTF-16/UTF-32 requires state management. */
typedef struct {
   boolean     bom_written;
   boolean     little_endian;
} ucs_state_t;

#endif	/* COMMON_DEFS_H */
