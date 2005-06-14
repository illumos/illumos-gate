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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	<a.out.h> - Object file structure declarations.
 */

struct aexec {				/* a.out header */
	unsigned short	xa_magic;	/* magic number */
	unsigned short	xa_text;	/* size of text segment */
	unsigned short	xa_data;	/* size of initialized data */
	unsigned short	xa_bss;		/* size of unitialized data */
	unsigned short	xa_syms;	/* size of symbol table */
	unsigned short	xa_entry;	/* entry point */
	unsigned short	xa_unused;	/* not used */
	unsigned short	xa_flag;	/* relocation info stripped */
};


/*
 *	Definitions for aexec.xa_magic, OCTAL, obsolete (short).
 */

#define	FMAGIC		0407	/* normal */
#define	NMAGIC		0410	/* pure, shared text */
#define	IMAGIC		0411	/* separate I & D */
#define	OMAGIC		0405	/* text overlays */
#define	ZMAGIC		0413	/* demand load format */

#define	A_MAGIC1	FMAGIC
#define	A_MAGIC2	NMAGIC
#define	A_MAGIC3	IMAGIC
#define	A_MAGIC4	OMAGIC

#define	ATEXTPOS(ap)	((long)sizeof (struct aexec))
#define	ADATAPOS(ap)	(ATEXTPOS(ap) + (long)(ap)->xa_text)
#define	ARTEXTPOS(ap)	(ADATAPOS(ap) + (long)(ap)->xa_data)
#define	ARDATAPOS(ap)	(ARTEXTPOS(ap) + ((long)\
	((ap)->xa_flag? 0 : (ap)->xa_text)))
#define	ASYMPOS(ap)	(ATEXTPOS(ap) + \
	(((ap)->xa_flag? 1L : 2L) * \
	((long)(ap)->xa_text + (long)(ap)->xa_data)))
#define	AENDPOS(ap)	(ASYMPOS(ap) + (long)(ap)->xa_syms)
