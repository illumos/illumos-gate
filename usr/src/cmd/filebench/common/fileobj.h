/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FB_FILEOBJ_H
#define	_FB_FILEOBJ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <pthread.h>

#include "vars.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fileobj {
	char		fo_name[128];	/* Name */
	struct fileobj	*fo_next;	/* Next in list */
	pthread_t	fo_tid;		/* Thread id, for par alloc */
	var_string_t	fo_path;	/* Pathname in fs */
	var_integer_t	fo_size;	/* Initial size */
	var_integer_t	fo_create;	/* Attr */
	var_integer_t	fo_prealloc;	/* Attr */
	var_integer_t	fo_paralloc;	/* Attr */
	var_integer_t	fo_reuse;	/* Attr */
	var_integer_t	fo_cached;	/* Attr */
	int		fo_attrs;	/* Attributes */
} fileobj_t;

#define	FILE_ALLOC_BLOCK (off64_t)1024 * 1024

fileobj_t *fileobj_define(char *);
fileobj_t *fileobj_find(char *);
int	fileobj_init(void);
int	fileobj_open(fileobj_t *fileobj, int attrs);
void	fileobj_iter(int (*cmd)(fileobj_t *, int));
int	fileobj_print(fileobj_t *fileobj, int first);
void	fileobj_usage(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_FILEOBJ_H */
