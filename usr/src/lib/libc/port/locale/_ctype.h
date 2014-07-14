/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __CTYPE_H_
#define	__CTYPE_H_

/*
 * Please take careful note.  It turns out that the _ISxxx macros
 * occupy the lower order byte, except for _ISGRAPH, _ISALPHA, and _ISPRINT.
 * Those occupt 0x2000, 0x4000, and 0x8000.  Now, noting *very* carefully,
 * it turns out that this leaves some gaps in the extended bits, which
 * are occupied by _E1 = phonogram, _E2 = ideogram, and _E3 = English.
 * The *other* _Ex bits are reserved.  We don't think these higher order
 * bits are baked into applications (because they haven't been used before),
 * so we believe it is safe to reuse them how we see fit.
 *
 * This makes it possible to define a single space which overlaps both the
 * wctype types, and the ctype types.
 */

#define	_CTYPE_A	_ISALPHA		/* Alpha */
#define	_CTYPE_C	_ISCNTRL		/* Control */
#define	_CTYPE_D	_ISDIGIT		/* Digit */
#define	_CTYPE_G	_ISGRAPH		/* Graph */
#define	_CTYPE_L	_ISLOWER		/* Lower */
#define	_CTYPE_P	_ISPUNCT		/* Punct */
#define	_CTYPE_S	_ISSPACE		/* Space */
#define	_CTYPE_U	_ISUPPER		/* Upper */
#define	_CTYPE_X	_ISXDIGIT		/* X digit */
#define	_CTYPE_B	_ISBLANK		/* Blank */
#define	_CTYPE_R	_ISPRINT		/* Print */

#define	_CTYPE_Q	_E1			/* Phonogram */
#define	_CTYPE_I	_E2			/* Ideogram */
#define	_CTYPE_E	_E3			/* English (Solaris) */
#define	_CTYPE_N	_E4			/* Number  */
#define	_CTYPE_T	_E5			/* Special */

/* These high order bits were never used for anything at all. */
#define	_CTYPE_SW0	0x20000000U		/* 0 width character */
#define	_CTYPE_SW1	0x40000000U		/* 1 width character */
#define	_CTYPE_SW2	0x80000000U		/* 2 width character */
#define	_CTYPE_SW3	0xc0000000U		/* 3 width character */
#define	_CTYPE_SWM	0xe0000000U		/* Mask for screen width data */
#define	_CTYPE_SWS	30			/* Bits to shift to get width */

#endif /* !__CTYPE_H_ */
