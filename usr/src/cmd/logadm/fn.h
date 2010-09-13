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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * logadm/fn.h -- public definitions for fn module
 */

#ifndef	_LOGADM_FN_H
#define	_LOGADM_FN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* functions that deal with single strings */
struct fn *fn_new(const char *s);
struct fn *fn_dup(struct fn *fnp);
struct fn *fn_dirname(struct fn *fnp);
void fn_setn(struct fn *fnp, int n);
int fn_getn(struct fn *fnp);
void fn_setstat(struct fn *fnp, struct stat *stp);
struct stat *fn_getstat(struct fn *fnp);
void fn_free(struct fn *fnp);
void fn_renew(struct fn *fnp, const char *s);
void fn_putc(struct fn *fnp, int c);
void fn_puts(struct fn *fnp, const char *s);
void fn_putfn(struct fn *fnp, struct fn *srcfnp);
void fn_rewind(struct fn *fnp);
int fn_getc(struct fn *fnp);
int fn_peekc(struct fn *fnp);
char *fn_s(struct fn *fnp);
boolean_t fn_isgz(struct fn *fnp);

/* functions that deal with lists of strings */
struct fn_list *fn_list_new(const char * const *slist);
struct fn_list *fn_list_dup(struct fn_list *fnlp);
void fn_list_free(struct fn_list *fnlp);
void fn_list_adds(struct fn_list *fnlp, const char *s);
void fn_list_addfn(struct fn_list *fnlp, struct fn *fnp);
void fn_list_rewind(struct fn_list *fnlp);
struct fn *fn_list_next(struct fn_list *fnlp);
void fn_list_addfn_list(struct fn_list *fnlp, struct fn_list *fnlp2);
void fn_list_appendrange(struct fn_list *fnlp,
    const char *s, const char *limit);
void fn_list_print(struct fn_list *fnlp, FILE *stream);
off_t fn_list_totalsize(struct fn_list *fnlp);
struct fn *fn_list_popoldest(struct fn_list *fnlp);
boolean_t fn_list_empty(struct fn_list *fnlp);
int fn_list_count(struct fn_list *fnlp);

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGADM_FN_H */
