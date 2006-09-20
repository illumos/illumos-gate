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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _UTIL_H
#define	_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* String tables */
typedef struct table_head_t {
	int nelem;
	int used;
	char *elements[1];	/* Actually elements[nelem] */
} table_t;

#define	TABLE_INITIAL	50
#define	TABLE_INCREMENT	50


extern char *get_stringtable(table_t *, int);
extern int in_stringtable(table_t *, const char *);
extern int in_stringset(char *, char *);
extern void print_stringtable(table_t *);
extern void sort_stringtable(table_t *);

/* Caveat: never discard return value: see note in .c file. */
extern table_t *add_to_stringtable(table_t *, char *);

extern table_t *create_stringtable(int);
extern table_t *free_stringtable(table_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTIL_H */
