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
 * Copyright 1999, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* inverted index definitions */

/* postings temporary file long number coding into characters */
#define	BASE		95	/* 127 - ' ' */
#define	PRECISION	5	/* maximum digits after converting a long */

/* inverted index access parameters */
#define	INVAVAIL	0
#define	INVBUSY		1
#define	INVALONE	2

/* boolean set operations */
#define	OR		3
#define	AND		4
#define	NOT		5
#define	REVERSENOT	6

/* note that the entire first block is for parameters */
typedef	struct	{
	long	version;	/* inverted index format version */
	long	filestat;	/* file status word  */
	long	sizeblk;	/* size of logical block in bytes */
	long	startbyte;	/* first byte of superfinger */
	long	supsize;	/* size of superfinger in bytes */
	long	cntlsize;	/* size of max cntl space (should be a */
				/* multiple of BUFSIZ) */
	long	share;		/* flag whether to use shared memory */
} PARAM;

typedef	struct {
	FILE	*invfile;	/* the inverted file ptr */
	FILE	*postfile;	/* posting file ptr */
	PARAM	param;		/* control parameters for the file */
	char	*iindex;	/* ptr to space for superindex */
	char	*logblk;	/* ptr to space for a logical block */
	long	numblk;		/* number of block presently at *logblk */
	long	keypnt;		/* number item in present block found */
	int	swap;		/* file endian mistmatch? */
} INVCONTROL;

typedef	struct	{
	short	offset;		/* offset in this logical block */
	unsigned char size;	/* size of term */
	unsigned char space;	/* number of longs of growth space */
	long	post;		/* number of postings for this entry */
} ENTRY;

typedef	struct {
	long	lineoffset;	/* source line database offset */
	long	fcnoffset;	/* function name database offset */
	long	fileindex : 24;	/* source file name index */
	long	type : 8;	/* reference type (mark character) */
} POSTING;

extern	long	*srcoffset;	/* source file name database offsets */
extern	int	nsrcoffset;	/* number of file name database offsets */

extern void	boolclear(void);
extern POSTING	*boolfile(INVCONTROL *invcntl, long *num, int bool);
extern void	invclose(INVCONTROL *invcntl);
extern long	invfind(INVCONTROL *invcntl, char *searchterm);
extern int	invforward(INVCONTROL *invcntl);
extern int	invopen(INVCONTROL *invcntl, char *invname, char *invpost,
		    int stat);
extern int	invterm(INVCONTROL *invcntl, char *term);
extern long	invmake(char *invname, char *invpost, FILE *infile);
