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
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_STABS_H
#define	_SYS_STABS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MAXLINE	8192

#define	BUCKETS	128

struct node {
	char *name;
	char *format;
	char *format2;
	struct child *child;
};

struct	child {
	char *name;
	char *format;
	struct child *next;
};

#define	HASH(NUM)		((int)(NUM & (BUCKETS - 1)))

enum type {
	INTRINSIC,
	POINTER,
	ARRAY,
	FUNCTION,
	STRUCT,
	UNION,
	ENUM,
	FORWARD,
	TYPEOF,
	VOLATILE,
	CONST
};

struct tdesc {
	char	*name;
	struct	tdesc *next;
	enum	type type;
	int	size;
	union {
		struct	tdesc *tdesc;		/* *, f , to */
		struct	ardef *ardef;		/* ar */
		struct members {		/* s, u */
			struct	mlist *forw;
			struct	mlist *back;
		} members;
		struct  elist *emem; 		/* e */
	} data;
	int	id;
	struct tdesc *hash;
};

struct elist {
	char	*name;
	int	number;
	struct elist *next;
};

struct element {
	struct tdesc *index_type;
	int	range_start;
	int	range_end;
};

struct ardef {
	struct tdesc	*contents;
	struct element	*indices;
};

struct mlist {
	int	offset;
	int	size;
	char	*name;
	struct	mlist *next;
	struct	mlist *prev;
	struct	tdesc *fdesc;		/* s, u */
};

struct model_info {
	char *name;
	size_t pointersize;
	size_t charsize;
	size_t shortsize;
	size_t intsize;
	size_t longsize;
};

extern struct tdesc *lookupname(char *);
extern void parse_input(void);
extern char *convert_format(char *format, char *dfault);
extern struct child *find_child(struct node *np, char *w);
extern char *uc(const char *s);

extern boolean_t error;
extern struct model_info *model;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_STABS_H */
