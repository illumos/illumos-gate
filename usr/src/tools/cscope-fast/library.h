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


/* library function return value declarations */

/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/* private library */
char	*compath(char *pathname);
char	*getwd(char *dir);
char	*logdir(char *name);
char	*mygetenv(char *variable, char *deflt);
char	*mygetwd(char *dir);

/* alloc.c */
char	*stralloc(char *s);
void	*mymalloc(size_t size);
void	*mycalloc(size_t nelem, size_t size);
void	*myrealloc(void *p, size_t size);

/* mypopen.c */
FILE	*mypopen(char *cmd, char *mode);
int	mypclose(FILE *ptr);

/* vp*.c */
FILE	*vpfopen(char *filename, char *type);
void	vpinit(char *currentdir);
int	vpopen(char *path, int oflag);
struct stat;
int	vpstat(char *path, struct stat *statp);

/* standard C library */
#include <stdlib.h>
#include <string.h>	/* string functions */
