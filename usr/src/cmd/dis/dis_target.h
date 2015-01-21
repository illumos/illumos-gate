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
 * Copyright 2011 Jason King.  All rights reserved.
 */

#ifndef	_DIS_TARGET_H
#define	_DIS_TARGET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gelf.h>
#include <sys/types.h>

/*
 * Basic types
 */
typedef struct dis_tgt dis_tgt_t;
typedef struct dis_func dis_func_t;
typedef struct dis_scn dis_scn_t;

/*
 * Target management
 */
dis_tgt_t *dis_tgt_create(const char *);
void dis_tgt_destroy(dis_tgt_t *);
const char *dis_tgt_lookup(dis_tgt_t *, uint64_t, off_t *, int, size_t *,
    int *);
const char *dis_find_section(dis_tgt_t *, uint64_t, off_t *);
const char *dis_tgt_name(dis_tgt_t *);
const char *dis_tgt_member(dis_tgt_t *);
void dis_tgt_ehdr(dis_tgt_t *, GElf_Ehdr *);
off_t dis_tgt_next_symbol(dis_tgt_t *, uint64_t);
dis_tgt_t *dis_tgt_next(dis_tgt_t *);

/*
 * Section management
 */
typedef void (*section_iter_f)(dis_tgt_t *, dis_scn_t *, void *);
void dis_tgt_section_iter(dis_tgt_t *, section_iter_f, void *);

int dis_section_istext(dis_scn_t *);
void *dis_section_data(dis_scn_t *);
size_t dis_section_size(dis_scn_t *);
uint64_t dis_section_addr(dis_scn_t *);
const char *dis_section_name(dis_scn_t *);
dis_scn_t *dis_section_copy(dis_scn_t *);
void dis_section_free(dis_scn_t *);

/*
 * Function management
 */
typedef void (*function_iter_f)(dis_tgt_t *, dis_func_t *, void *);
void dis_tgt_function_iter(dis_tgt_t *, function_iter_f, void *);
dis_func_t *dis_tgt_function_lookup(dis_tgt_t *, const char *);

void *dis_function_data(dis_func_t *);
size_t dis_function_size(dis_func_t *);
uint64_t dis_function_addr(dis_func_t *);
const char *dis_function_name(dis_func_t *);
dis_func_t *dis_function_copy(dis_func_t *);
void dis_function_free(dis_func_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DIS_TARGET_H */
