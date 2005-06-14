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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/
/* LINTLIBRARY */


#include	<errno.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	"lp.h"
#include	"msgs.h"

static	fifobuffer_t	**FifoBufferTable	= NULL;
static	int		FifoBufferTableSize	= 0;

/*
**	Local functions
*/
static	int		InitFifoBufferTable (void);
static	int		GrowFifoBufferTable (int);
static	fifobuffer_t	*NewFifoBuffer (int);


int
ResetFifoBuffer(int fd)
{
	if ((!FifoBufferTableSize) && (InitFifoBufferTable () < 0))
		return	-1;

	if (fd >= FifoBufferTableSize)
		return	0;

	if (FifoBufferTable [fd]) {
		FifoBufferTable [fd]->full = 0;
		FifoBufferTable [fd]->psave =
		FifoBufferTable [fd]->psave_end = 
			FifoBufferTable [fd]->save;
	}
	return	0;
}


fifobuffer_t *
GetFifoBuffer(int fd)
{
	if (fd < 0) {
		errno = EINVAL;
		return	NULL;
	}
	if ((fd >= FifoBufferTableSize) && (GrowFifoBufferTable (fd) < 0))
		return	NULL;

	if (!FifoBufferTable [fd]) {
		if (!NewFifoBuffer (fd))
			return	NULL;
		
		FifoBufferTable [fd]->full = 0;
		FifoBufferTable [fd]->psave =
		FifoBufferTable [fd]->psave_end = 
			FifoBufferTable [fd]->save;
	}
	
	return	FifoBufferTable [fd];
}


static	int
InitFifoBufferTable()
{
	if (FifoBufferTableSize)
		return	0;

	FifoBufferTable = (fifobuffer_t **)
		Calloc (100, sizeof (fifobuffer_t *));
	if (!FifoBufferTable)
		return	-1;	/* ENOMEM is already set. */

	FifoBufferTableSize = 100;

	return	0;
}


static int
GrowFifoBufferTable (int fd)
{
	fifobuffer_t	**newpp;

	newpp = (fifobuffer_t **)
		Realloc ((void*)FifoBufferTable,
		(fd+10)*sizeof (fifobuffer_t *));
	if (!newpp)
		return	-1;	/* ENOMEM is already set. */

	FifoBufferTableSize = fd+10;

	return	0;
}


static fifobuffer_t *
NewFifoBuffer(int fd)
{
	int	i;

	for (i=0; i < FifoBufferTableSize; i++)
	{
		if (FifoBufferTable [i] &&
		    Fcntl (i, F_GETFL) < 0 &&
                    errno == EBADF)
		{
			FifoBufferTable [fd] = FifoBufferTable [i];
			FifoBufferTable [i] = NULL;
			return	FifoBufferTable [fd];
		}
	}
	FifoBufferTable [fd] = (fifobuffer_t *)
		Calloc (1, sizeof (fifobuffer_t));

	return	FifoBufferTable [fd];
}
