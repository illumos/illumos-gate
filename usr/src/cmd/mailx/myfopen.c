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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rcv.h"

#undef	fopen
#undef	fclose

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Local version of fopen() and fclose(). These maintain a list of
 * file pointers which can be run down when we need to close
 * all files, such as before executing external commands.
 */

static NODE	*append();
static NODE	*del1();
static NODE	*getnode();
static NODE	*search();

static NODE *
getnode(FILE *fp)
{
	NODE *newnode;

	if ((newnode = (NODE *)malloc(sizeof(NODE))) == (NODE *)NULL) {
		(void) fputs("Cannot allocate node space\n", stderr);
		exit(3);
	}
	newnode->fp = fp;
	newnode->next = (NODE *)NULL;
	return(newnode);
}

static NODE *
search(FILE *fp)
{
	register NODE *tmp;
	
	for (tmp = fplist; tmp != (NODE *)NULL; tmp = tmp->next)
		if (tmp->fp == fp)
			break;
	return( tmp != (NODE *)NULL ? tmp : NOFP);
}
	
static NODE *
append(FILE *fp)
{
	register NODE *newnode;

	if ((newnode = getnode(fp)) == (NODE *)NULL)
		return(NOFP);
	if (fplist == NOFP) {
		fplist = newnode;
	} else {
		newnode->next = curptr->next;
		curptr->next = newnode;
	}
	return(newnode);
}

static NODE *
del1(NODE *oldcur)
{
	register NODE *cur, *prev;

	for (prev = cur = fplist; cur != (NODE *)NULL; cur = cur->next) {
		if (cur == oldcur) {
			if (cur == fplist) {
				cur = fplist = cur->next;
			} else {
				prev->next = cur->next;
				cur = prev->next ? prev->next : prev;
			}
			if (curptr == oldcur)
				curptr = prev;
			free(oldcur);
			break;
		}
		prev = cur;
	}
	return(cur);
}

FILE *
my_fopen(char *file, char *mode)
{
	FILE *fp;

	if ((fp = fopen(file, mode)) == (FILE *)NULL) {
		fplist = NOFP;
		return(fp);
	} else {
		curptr = append(fp);
	}
	return(fp);
}

int
my_fclose(register FILE *iop)
{
	register NODE *cur;

	int ret = fclose(iop);
	if (fplist != NOFP) {
		cur = search(iop);
		cur = del1(cur);
	}
	return ret;
}
