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
 * Copyright (c) 1996-1997 by Sun Microsystems, Inc.
 * All rights reserved.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ********************************************************************
 *                         COPYRIGHT NOTICE                           *
 * ********************************************************************
 *        This software is copyright (C) 1982 by Pavel Curtis         *
 *                                                                    *
 *        Permission is granted to reproduce and distribute           *
 *        this file by any means so long as no fee is charged         *
 *        above a nominal handling fee and so long as this            *
 *        notice is always included in the copies.                    *
 *                                                                    *
 *        Other rights are reserved except as explicitly granted      *
 *        by written permission of the author.                        *
 *                Pavel Curtis                                        *
 *                Computer Science Dept.                              *
 *                405 Upson Hall                                      *
 *                Cornell University                                  *
 *                Ithaca, NY 14853                                    *
 *                                                                    *
 *                Ph- (607) 256-4934                                  *
 *                                                                    *
 *                Pavel.Cornell@Udel-Relay   (ARPAnet)                *
 *                decvax!cornell!pavel       (UUCPnet)                *
 * ********************************************************************
 */

/*
 *	read_entry.c -- Routine for reading in a compiled terminfo file
 *
 *  $Log:	RCS/read_entry.v $
 * Revision 2.1  82/10/25  14:49:55  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:18:22  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:31:15  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:11:49  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  22:25:13  pavel
 * Initial revision
 *
 *
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "curses_inc.h"
#include "object.h"

#define	OFFSET_BUFSIZE	100

#define	swap(x)		(((x >> 8) & 0377) + 256 * (x & 0377))

#define	min(a, b)	((a) > (b)  ?  (b)  :  (a))

/*
 *	int
 *	read_entry(filename, ptr)
 *
 *	Read the compiled terminfo entry in the given file into the
 *	structure pointed to by ptr, allocating space for the string
 *	table and placing its address in ptr->str_table.
 *
 */

static char	TermNames[128];	/* Buffer for terminal names for first term */
static char	StringTable[2048];	/* String table for first terminal  */
static int	beencalled = 0;	/* read_entry has been called before	    */

int
read_entry(filename, bptr, nptr, sptr)
char			*filename;
struct _bool_struct	*bptr;
struct _num_struct	*nptr;
struct _str_struct	*sptr;
{
	int		fd;
	int		numread;
	int		num_strings;
	int		cur_string;
	int		i;
	struct header	header;
	unsigned char	bytebuf[2];
	char		ch;
	char *UB;	/* booleans */
	short *UN;	/* numbers */
	char **US;	/* strings */
	char *pst;	/* pointer to string table */
	int swapping = must_swap();
	extern int BoolCount;
	extern int NumCount;
	extern int StrCount;
	extern long lseek();
	unsigned char byte[OFFSET_BUFSIZE][2];
	short number[OFFSET_BUFSIZE];

	fd = open(filename, 0);

	if (fd < 0)
		return (-1);

	read(fd, &header, sizeof (header));

	if (swapping) {
		header.magic = swap(header.magic);
		header.name_size = swap(header.name_size);
		header.bool_count = swap(header.bool_count);
		header.num_count = swap(header.num_count);
		header.str_count = swap(header.str_count);
		header.str_size = swap(header.str_size);
	}

	if (header.magic != MAGIC) {
		close(fd);
		return (-1);
	}

	read(fd, TermNames, min(127, header.name_size));
	TermNames[127] = '\0';
	if (header.name_size > 127)
		lseek(fd, (long)(header.name_size - 127), 1);

	UB = &(bptr->_auto_left_margin);
	UN = &(nptr->_columns);
	US = &(sptr->strs._back_tab);
	read(fd, UB, min(BoolCount, header.bool_count));
	if (header.bool_count > BoolCount)
		lseek(fd, (long)(header.bool_count - BoolCount), 1);
	else
		for (i = header.bool_count; i < BoolCount; i++)
			UB[i] = 0;

	if ((header.name_size + header.bool_count) % 2 != 0)
		read(fd, &ch, 1);

	if (!swapping)
		read(fd, (char *)UN, min(NumCount, header.num_count) * 2);
	else {
		for (i = 0; i < min(header.num_count, NumCount); i++) {
			read(fd, (char *)bytebuf, 2);
			if (bytebuf[1] == 0377) {
				if (bytebuf[0] == 0376)	/* -2 == cancelled */
					UN[i] = -2;
				else if (bytebuf[0] == 0377)
					/* -1 == not there */
					UN[i] = -1;
				else
					UN[i] = bytebuf[0] + 256 * bytebuf[1];
			} else
				UN[i] = bytebuf[0] + 256 * bytebuf[1];
		}
	}

	if (header.num_count > NumCount)
		lseek(fd, (long)(2 * (header.num_count - NumCount)), 1);
	else
		for (i = header.num_count; i < NumCount; i++)
			UN[i] = -1;

	if (beencalled) {
		/* beencalled is non-zero only if we've been called */
		pst = malloc((unsigned)header.str_size);
		if (pst == NULL) {
			close(fd);
			return (-1);
		}
	} else {
		pst = StringTable;
		beencalled++;
	}

	num_strings = min(StrCount, header.str_count);
	cur_string = 0;

	while (num_strings > 0) {

		if (swapping) {
			numread = read(fd, byte, 2*min(num_strings,
							OFFSET_BUFSIZE));
			if (numread <= 0) {
				close(fd);
				return (-1);
			}
			for (i = 0; i < numread / 2; i++) {
				if (byte[i][0] == 0377 && byte[i][1] == 0377)
									/* -1 */
					US[i + cur_string] = 0;
				else if (byte[i][0] == 0376 &&
							byte[i][1] == 0377)
								/* -2 */
					US[i + cur_string] = (char *)-1;
				else
					US[i + cur_string] = (byte[i][0] +
							256*byte[i][1]) + pst;
			}
		} else {
			numread = read(fd, number, 2*min(num_strings,
							OFFSET_BUFSIZE));
			if (numread <= 0) {
				close(fd);
				return (-1);
			}
			for (i = 0; i < numread / 2; i++) {
				if (number[i] == -1)	/* not there */
					US[i + cur_string] = 0;
				else if (number[i] == -2)	/* cancelled */
					US[i + cur_string] = (char *)-1;
				else
					US[i + cur_string] = number[i] + pst;
			}
		}

		cur_string += numread / 2;
		num_strings -= numread / 2;
	}

	if (header.str_count > StrCount)
		lseek(fd, (long)(2 * (header.str_count - StrCount)), 1);
	else for (i = header.str_count; i < StrCount; i++)
		US[i] = 0;

	numread = read(fd, pst, header.str_size);
	close(fd);
	if (numread != header.str_size)
		return (-1);

	return (0);
}

/*
 *	int
 *	must_swap()
 *
 *	Test whether this machine will need byte-swapping
 *
 */

int
must_swap()
{
	union {
	    short num;
	    char  byte[2];
	} test;

	test.num = 1;
	return (test.byte[1]);
}
