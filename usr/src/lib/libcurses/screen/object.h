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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#ifndef	_OBJECT_H
#define	_OBJECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

/*
 *			COPYRIGHT NOTICE
 *
 *	This software is copyright(C) 1982 by Pavel Curtis
 *
 *	Permission is granted to reproduce and distribute
 *	this file by any means so long as no fee is charged
 *	above a nominal handling fee and so long as this
 *	notice is always included in the copies.
 *
 *	Other rights are reserved except as explicitly granted
 *	by written permission of the author.
 *		Pavel Curtis
 *		Computer Science Dept.
 *		405 Upson Hall
 *		Cornell University
 *		Ithaca, NY 14853
 *
 *		Ph- (607) 256-4934
 *
 *		Pavel.Cornell@Udel-Relay   (ARPAnet)
 *		decvax!cornell!pavel(UUCPnet)
 */

/*
 * $Header:   RCS/object.v  Revision 2.1  82/10/25  14:49:50  pavel  Exp$
 *
 *	object.h - Format of compiled terminfo files
 *
 *		Header(12 bytes), containing information given below
 *		Names Section, containing the names of the terminal
 *		Boolean Section, containing the values of all of the
 *				boolean capabilities
 *				A null byte may be inserted here to make
 *				sure that the Number Section begins on an
 *				even word boundary.
 *		Number Section, containing the values of all of the numeric
 *				capabilities, each as a short integer
 *		String Section, containing short integer offsets into the
 *				String Table, one per string capability
 *		String Table, containing the actual characters of the string
 *				capabilities.
 *
 *	NOTE that all short integers in the file are stored using VAX/PDP-style
 *	byte-swapping, i.e., least-significant byte first.  The code in
 *	read_entry() automatically fixes this up on machines which don't use
 *	this system(I hope).
 *
 *  $Log:	RCS/object.v $
 * Revision 2.1  82/10/25  14:49:50  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:18:19  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:31:12  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:10:18  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  18:48:55  pavel
 * Initial revision
 *
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAGIC	0432

struct header
{
	short	magic;		/* Magic Number (0432)			*/
	short	name_size;	/* Size of names section		*/
	short	bool_count;	/* Number of booleans			*/
	short	num_count;	/* Number of numbers			*/
	short	str_count;	/* Number of strings			*/
	short	str_size;	/* Size of string table			*/
};

#ifdef	__cplusplus
}
#endif

#endif	/* _OBJECT_H */
