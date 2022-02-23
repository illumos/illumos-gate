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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

/*
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_DIFF_H
#define	_DIFF_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Output format options
 */

int	opt;

#define	D_NORMAL	0	/* Normal output */
#define	D_EDIT		-1	/* Editor script out */
#define	D_REVERSE	1	/* Reverse editor script */
#define	D_CONTEXT	2	/* Diff with context */
#define	D_IFDEF		3	/* Diff with merged #ifdef's */
#define	D_NREVERSE	4	/* Reverse ed script with numbered */
				/* lines and no trailing . */

/*
 * Constant declarations
 */
#define	HALFMASK	0xf

#define	prints(s)	fputs(s, stdout)

#define	MAX_CONTEXT	128

/*
 * diff - directory comparison
 */
#define	d_flags	d_ino

#define	ONLY	1		/* Only in this directory */
#define	SAME	2		/* Both places and same */
#define	DIFFER	4		/* Both places and different */
#define	DIRECT	8		/* Directory */

struct dir {
	ulong_t		d_ino;
	int16_t		d_reclen;
	int16_t		d_namlen;
	char		*d_entry;
};


/*
 * type definitions
 */

struct cand {
	int x;
	int y;
	int pred;
} cand;

struct line {
	int serial;
	int value;
} *file[2], line;

/*
 * The following struct is used to record change information when
 * doing a "context" diff.  (see routine "change" to understand the
 * highly mneumonic field names)
 */
struct context_vec {
	int	a;	/* start line in old file */
	int	b;	/* end line in old file */
	int	c;	/* start line in new file */
	int	d;	/* end line in new file */
};


/*
 * Algorithm related options
 */
int bflag = 0;
int tflag = 0;
int wflag = 0;
int iflag = 0;
int qflag = 0;
int rflag = 0;
int lflag = 0;
int sflag = 0;
int hflag = 0;
int uflag = 0;

/*
 * Variables for D_IFDEF option.
 */
int wantelses = 0;	/* used with D_IFDEF */
char *ifdef1, *ifdef2;  /* hold the ifdef strings */
char *endifname;
int inifdef = 0;

/*
 * Variables for -C (-c) context option.
 */
int context = 0;	/* number of lines specfied with the C flag */

char *empty = "";	/* the empty string */

char **diffargv;	/* keep track of argv for diffdir */

char start[256];	/* specify where to start, used with -S */

FILE *input[2];		/* two input files */
int  len[2];
struct line *sfile[2];  /* shortened by pruning common prefix and suffix */
int  slen[2];

struct stat stb1;

/*
 * Input file names.
 * With diffdir, file1 and file2 are allocated BUFSIZ space,
 * and padded with a '/', and then efile0 and efile1 point after
 * the '/'.
 */
char	*file1, *file2, *efile1, *efile2;
struct	stat stb1, stb2;

/*
 * input_file1 and input_file2 are to display
 * the filenames in the output
 */
char	*input_file1, *input_file2;

char pr[] = "/usr/bin/pr";
char diff[] = "/usr/bin/diff";
char diffh[] = "/usr/lib/diffh";
int status = 2;
int anychange = 0;

struct	context_vec	*context_vec_start,
			*context_vec_end,
			*context_vec_ptr;

char tempfile[2][16];	/* used when comparing against std input */
			/* or char special devices */
int whichtemp;

#ifdef	__cplusplus
}
#endif

#endif	/* _DIFF_H */
