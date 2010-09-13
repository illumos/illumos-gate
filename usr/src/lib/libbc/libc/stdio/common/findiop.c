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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include "iob.h"

#define active(iop)	((iop)->_flag & (_IOREAD|_IOWRT|_IORW))

static unsigned char sbuf[NSTATIC][_SBFSIZ];
unsigned char (*_smbuf)[_SBFSIZ] = sbuf;
static	FILE	**iobglue;
static	FILE	**endglue;

/*
 * Find a free FILE for fopen et al.
 * We have a fixed static array of entries, and in addition
 * may allocate additional entries dynamically, up to the kernel
 * limit on the number of open files.
 * At first just check for a free slot in the fixed static array.
 * If none are available, then we allocate a structure to glue together
 * the old and new FILE entries, which are then no longer contiguous.
 */
FILE *
_findiop(void)
{
	FILE **iov, *iop;
	FILE *fp;

	if(iobglue == NULL) {
		for(iop = _iob; iop < _iob + NSTATIC; iop++)
			if(!active(iop))
				return(iop);

		if(_f_morefiles() == 0) {
			errno = ENOMEM;
			return(NULL);
		}
	}

	iov = iobglue;
	while(*iov != NULL && active(*iov))
		if (++iov >= endglue) {
			errno = EMFILE;
			return(NULL);
		}

	if(*iov == NULL)
		*iov = (FILE *)calloc(1, sizeof **iov);

	return(*iov);
}

int
_f_morefiles(void)
{
	FILE **iov;
	FILE *fp;
	unsigned char *cp;
	int nfiles;

	nfiles = getdtablesize();

	iobglue = (FILE **)calloc(nfiles, sizeof *iobglue);
	if(iobglue == NULL)
		return(0);

	if((_smbuf = (unsigned char (*)[_SBFSIZ])malloc(nfiles * sizeof *_smbuf)) == NULL) {
		free((char *)iobglue);
		iobglue = NULL;
		return(0);
	}

	endglue = iobglue + nfiles;

	for(fp = _iob, iov = iobglue; fp < &_iob[NSTATIC]; /* void */)
		*iov++ = fp++;

	return(1);
}

void
f_prealloc(void)
{
	FILE **iov;
	FILE *fp;

	if(iobglue == NULL && _f_morefiles() == 0)
		return;

	for(iov = iobglue; iov < endglue; iov++)
		if(*iov == NULL)
			*iov = (FILE *)calloc(1, sizeof **iov);
}

void
_fwalk(int (*function)(FILE *))
{
	FILE **iov;
	FILE *fp;

	if(function == NULL)
		return;

	if(iobglue == NULL) {
		for(fp = _iob; fp < &_iob[NSTATIC]; fp++)
			if(active(fp))
				(*function)(fp);
	} else {
		for(iov = iobglue; iov < endglue; iov++)
			if(*iov && active(*iov))
				(*function)(*iov);
	}
}
