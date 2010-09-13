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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * m_ord.c
 *
 * Copyright 1986, 1993 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * FUNCTIONS:
 *   m_ord(c)
 *   m_chr(i)
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/mks/rcs/m_ord.c 1.13 1993/05/19 18:52:15 ant Exp $";
#endif
#endif

#include <mks.h>
#include <ctype.h>

/*
 * Given an English alphabetic letter, return an ordinal number.
 * If the character is not an English letter then return -1.
 *
 * This is most useful for handling the fact that POSIX.2 does not
 * have a requirement that the English alpha letters be in sequential
 * order in the character set.  This would mean that the following is
 * non-portable to non-ASCII machines:
 *
 * 	index = letter - 'a';
 *
 * The only solution possible was to have a mapping function to
 * convert the alpha letters to their one (1) based ordinal value.
 *
 * 	index = m_ord(letter) - 1;
 */

/*f
 *   m_ord(c) : convert character(case insensitive) to an an ordinal value.
 *              if c is an alphabetic character (A-Z,a-z), this returns
 *              a number between 1 and 26
 */
int
m_ord(c)
wint_t c;
{
	/*  note: this implementation is code set independent  */
	switch (towupper(c)) { 	
		case 'A': return 1;
		case 'B': return 2;
		case 'C': return 3;
		case 'D': return 4;
		case 'E': return 5;
		case 'F': return 6;
		case 'G': return 7;
		case 'H': return 8;
		case 'I': return 9;
		case 'J': return 10;
		case 'K': return 11;
		case 'L': return 12;
		case 'M': return 13;
		case 'N': return 14;
		case 'O': return 15;
		case 'P': return 16;
		case 'Q': return 17;
		case 'R': return 18;
		case 'S': return 19;
		case 'T': return 20;
		case 'U': return 21;
		case 'V': return 22;
		case 'W': return 23;
		case 'X': return 24;
		case 'Y': return 25;
		case 'Z': return 26;
		default : return -1;
	}
}

/*f
 *   m_chr(i) : convert an ordinal value to its corresponding character
 *              using the reverse mapping as m_ord().
 *              if i is a number between 1 and 26 it returns
 *              a character between A-Z
 *
 */
wint_t
m_chr(i)
int i;
{
	/*  note: this implementation is code set independent  */
	switch (i) { 	
		case 1: return 'A';
		case 2: return 'B';
		case 3: return 'C';
		case 4: return 'D';
		case 5: return 'E';
		case 6: return 'F';
		case 7: return 'G';
		case 8: return 'H';
		case 9: return 'I';
		case 10: return 'J';
		case 11: return 'K';
		case 12: return 'L';
		case 13: return 'M';
		case 14: return 'N';
		case 15: return 'O';
		case 16: return 'P';
		case 17: return 'Q';
		case 18: return 'R';
		case 19: return 'S';
		case 20: return 'T';
		case 21: return 'U';
		case 22: return 'V';
		case 23: return 'W';
		case 24: return 'X';
		case 25: return 'Y';
		case 26: return 'Z';
		default : return -1;
	}
}

#ifdef TEST
main()
{
	int A,Z,a,z;

	A = m_ord('A');
	Z = m_ord('Z');
	a = m_ord('a');
	z = m_ord('z');
	printf("ord(A) = %d, ord(Z) = %d, m_chr(A) = '%c', m_chr(Z) = '%c'\n",
		A, Z, m_chr(A), m_chr(Z));
	printf("ord(a) = %d, ord(z) = %d, m_chr(a) = '%c', m_chr(z) = '%c'\n",
		a, z, m_chr(a), m_chr(z));

	printf("ord(0x100) = %d, ord(0) = %d\n", m_ord(0x100), m_ord(0));
	printf("chr(0x100) = %d, chr(0) = %d\n", m_chr(0x100), m_chr(0));
}
#endif /*TEST*/
