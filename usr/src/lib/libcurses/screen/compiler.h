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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_COMPILER_H
#define	_COMPILER_H

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
 *		Pavel.Cornell@Udel-Relay(ARPAnet)
 *		decvax!cornell!pavel		(UUCPnet)
 */


/*
 *	compiler.h - Global variables and structures for the terminfo
 *			compiler.
 *
 *  $Header:   RCS/compiler.v  Revision 2.1  82/10/25  14:46:04  pavel  Exp$
 *
 *  $Log:	RCS/compiler.v $
 * Revision 2.1  82/10/25  14:46:04  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:17:20  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:30:09  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:10:10  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  18:38:11  pavel
 * Initial revision
 *
 */

#include <stdio.h>
#include <signal.h>   /* use this file to determine if this is SVR4.0 system */
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef TRUE
#define	TRUE	1
#define	FALSE	0
#endif

#ifndef EXTERN				/* for machines w/o multiple externs */
#define	EXTERN extern
#endif /* EXTERN */

#define	SINGLE			/* only one terminal (actually none) */

extern char	*destination;	/* destination directory for object files */

EXTERN long	start_time;	/* time at start of compilation */

EXTERN int	curr_line;	/* current line # in input */
EXTERN long	curr_file_pos;	/* file offset of current line */

EXTERN int	debug_level;	/* level of debugging output */

#define	DEBUG(level, fmt, a1) \
		if (debug_level >= level)\
		    fprintf(stderr, fmt, a1);

	/*
	 *	These are the types of tokens returned by the scanner.
	 *	The first three are also used in the hash table of capability
	 *	names.  The scanner returns one of these values after loading
	 *	the specifics into the global structure curr_token.
	 *
	 */

#define	BOOLEAN	0	/* Boolean capability */
#define	NUMBER	1	/* Numeric capability */
#define	STRING	2	/* String-valued capability */
#define	CANCEL	3	/* Capability to be cancelled in following tc's */
#define	NAMES	4	/* The names for a terminal type */
#define	UNDEF	5	/* Invalid token type */

#define	MAXBOOLS 64	/* Maximum # of boolean caps we can handle */
#define	MAXNUMS	64	/* Maximum # of numeric caps we can handle */
#define	MAXSTRINGS 512	/* Maximum # of string caps we can handle */

	/*
	 *	The global structure in which the specific parts of a
	 *	scanned token are returned.
	 *
	 */

struct token
{
	char	*tk_name;		/* name of capability */
	int	tk_valnumber;	/* value of capability (if a number) */
	char	*tk_valstring;	/* value of capability (if a string) */
};

EXTERN struct token	curr_token;

	/*
	 *	The file comp_captab.c contains an array of these structures,
	 *	one per possible capability.  These are then made into a hash
	 *	table array of the same structures for use by the parser.
	 *
	 */

struct name_table_entry
{
	struct name_table_entry *nte_link;
	char	*nte_name;	/* name to hash on */
	int	nte_type;	/* BOOLEAN, NUMBER or STRING */
	short	nte_index;	/* index of associated variable in its array */
};

extern struct name_table_entry	cap_table[];
extern struct name_table_entry	*cap_hash_table[];

extern int	Captabsize;
extern int	Hashtabsize;
extern int	BoolCount;
extern int	NumCount;
extern int	StrCount;

#define	NOTFOUND	((struct name_table_entry *)0)
	/*
	 *	Function types
	 *
	 */

struct name_table_entry	*find_entry();	/* look up entry in hash table */

int	next_char();
int	trans_string();

#ifdef SIGSTOP	/* SVR4.0 and beyond */
#define	SRCDIR "/usr/share/lib/terminfo"
#else
#define	SRCDIR "/usr/lib/terminfo"
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _COMPILER_H */
