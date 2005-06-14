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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 1.2	*/



/*
 * Member handling
 *	Archive members have an ASCII header.  A Member structure
 *	holds internal information.  Because the ASCII file header
 *	may be clobbered, Member holds a private, safe copy.
 *	The ar_name member of m_hdr points at m_name except for string
 *	table names.  Ar_rawname in m_hdr always points at m_raw.
 *
 *	m_raw	The original ar_name with null termination.
 *		E.g., "name/           "
 *
 *	m_name	The processed name, with '/' terminator changed to '\0'.
 *		Unused for string table names.  E.g., "name\0           "
 *
 *	To improve performance of member lookup we allocate lists which
 * 	contain MEMIDENTNO members:
 *
 *	ed_memlist -->   ---------------------
 *			|       m_next        |
 *			|       m_end         |
 *			|       m_free        |
 *			|---------------------|
 *			| m_offset | m_member |
 *			| m_offset | m_member |
 *			|     "    |    "     |
 *			 ---------------------
 */


#define	ARSZ(m)		(sizeof ((struct ar_hdr *)0)->m)

#define	MEMIDENTNO	126

struct	Member
{
	Elf_Arhdr	m_hdr;
	int		m_err;
	long		m_slide;
	char		m_raw[ARSZ(ar_name)+1];
	char		m_name[ARSZ(ar_name)+1];
};

struct	Memident
{
	char *		m_offset;
	struct Member *	m_member;
};

struct	Memlist
{
	struct Memlist *	m_next;
	struct Memident *	m_end;
	struct Memident *	m_free;
};
