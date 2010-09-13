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
	int	nelem;
	int	used;
	char	*elements[1]; /* Actually elements[nelem] */
} table_t;


/* Debugging information */
extern void print_metainfo(const Meta_info *);
extern void print_translatorinfo(const Translator_info *);

extern char *get_string_table(table_t *, int);
extern table_t *add_string_table(table_t *, char *);
extern table_t *create_string_table(int);
extern table_t *free_string_table(table_t *);
extern int in_string_table(table_t *, char *);
extern int in_string_set(char *, char *);
extern void print_string_table(table_t *);
extern void sort_string_table(table_t *);

/* Generic parsing of strings */
extern char *strnormalize(char *);
extern char *strtrim(char *);
extern char *strlower(char *);
extern char *strset(char *, char *);
extern char *strend(char *);
extern char *lastspace(char *);
extern char *skipb(char *);
extern char *nextb(char *);
extern char *skipsep(char *);
extern char *nextsep(char *);
extern char *nextsep2(char *);
extern char *objectname(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _UTIL_H */
