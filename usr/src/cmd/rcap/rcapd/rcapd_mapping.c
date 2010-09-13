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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include "rcapd_mapping.h"
#include "utils.h"

/*
 * lmapping_t is a list of non-overlapping mappings, ordered by address.  These
 * functions add, remove, and verify the existence of mappings in such a list.
 * rcapd_scanner.c is a consumer.
 */

typedef struct lmapping_find_cb_arg {
	uintptr_t	lmfa_addr;
	size_t		lmfa_size;
	lmapping_t	*lmfa_prior;
	lmapping_t	*lmfa_ret;
} lmapping_find_cb_arg_t;

#ifdef DEBUG
/*
 * Verify a sublist is properly ordered.
 */
static void
lmapping_verify(lmapping_t *lm)
{
	while (lm != NULL) {
		if (lm->lm_next != NULL)
			ASSERT(lm->lm_next->lm_addr > lm->lm_addr);
		lm = lm->lm_next;
	}
}
#else /* !DEBUG */
#define	lmapping_verify(x) ((void)0)
#endif /* DEBUG */

/*
 * Determine the position of a mapping with the given address and size.  Upon
 * return, lmfa_ret will be set to the actual mapping, if it exists, and
 * lmfa_prior will be set to the mapping which does or would precede one with
 * the given characteristics.
 */
static int
lmapping_find_cb(lmapping_t *lm, void *arg)
{
	lmapping_find_cb_arg_t *lmfa = arg;

	if (lm->lm_addr >= lmfa->lmfa_addr) {
		if (lmfa->lmfa_addr == lm->lm_addr && lmfa->lmfa_size ==
		    lm->lm_size)
			lmfa->lmfa_ret = lm;
		return (1);
	} else
		lmfa->lmfa_prior = lm;

	return (0);
}

static void
lmapping_walk(lmapping_t *lm, int(*lmapping_walk_cb)(lmapping_t *, void *),
    void *arg)
{
	lmapping_t *next;

	while (lm != NULL) {
		next = lm->lm_next;
		lmapping_verify(lm);
		if (lmapping_walk_cb(lm, arg) != 0) {
			lmapping_verify(lm);
			return;
		}
		lm = next;
	}
}

int
lmapping_remove(lmapping_t **lm, uintptr_t addr, size_t size)
{
	lmapping_find_cb_arg_t lmfa;

	lmfa.lmfa_addr = addr;
	lmfa.lmfa_size = size;
	lmfa.lmfa_prior = lmfa.lmfa_ret = NULL;

	lmapping_verify(*lm);
	lmapping_walk(*lm, lmapping_find_cb, &lmfa);
	if (lmfa.lmfa_ret == NULL)
		return (-1);

	if (lmfa.lmfa_prior != NULL)
		lmfa.lmfa_prior->lm_next = lmfa.lmfa_ret->lm_next;
	else if (*lm == lmfa.lmfa_ret)
		*lm = lmfa.lmfa_ret->lm_next;

	free(lmfa.lmfa_ret);

	lmapping_verify(*lm);

	return (0);
}

int
lmapping_insert(lmapping_t **lm, uintptr_t addr, size_t size)
{
	lmapping_find_cb_arg_t lmfa;
	lmapping_t *cur;

	cur = malloc(sizeof (*cur));
	if (cur == NULL)
		return (-1);

	cur->lm_addr = addr;
	cur->lm_size = size;
	cur->lm_next = NULL;

	lmfa.lmfa_addr = addr;
	lmfa.lmfa_size = size;
	lmfa.lmfa_prior = lmfa.lmfa_ret = NULL;

	lmapping_verify(*lm);
	lmapping_walk(*lm, lmapping_find_cb, &lmfa);
	ASSERT(lmfa.lmfa_ret == NULL);
	if (lmfa.lmfa_prior != NULL) {
		cur->lm_next = lmfa.lmfa_prior->lm_next;
		lmfa.lmfa_prior->lm_next = cur;
	} else {
		cur->lm_next = *lm;
		*lm = cur;
	}

	lmapping_verify(*lm);

	return (0);
}

int
lmapping_contains(lmapping_t *lm, uintptr_t addr, size_t size)
{
	lmapping_find_cb_arg_t lmfa;

	lmfa.lmfa_addr = addr;
	lmfa.lmfa_size = size;
	lmfa.lmfa_ret = NULL;

	lmapping_walk(lm, lmapping_find_cb, &lmfa);
	return (lmfa.lmfa_ret != NULL);
}

/*ARGSUSED*/
static int
lmapping_free_cb(lmapping_t *lm, void *arg)
{
	free(lm);
	return (0);
}

void
lmapping_free(lmapping_t **lm)
{
	lmapping_walk(*lm, lmapping_free_cb, NULL);
	*lm = NULL;
}

#ifdef DEBUG
int
lmapping_dump_diff(lmapping_t *lm1, lmapping_t *lm2)
{
	lmapping_t **lmv;
	int res = 0;
	int ch = 0;
	int label_printed = 0;

#define	OUTPUT_LABEL() \
	if (label_printed == 0) { \
		debug("changes in mappings:\n"); \
		label_printed++; \
	}

	while (lm1 != NULL && lm2 != NULL) {
		if ((lm1->lm_addr != lm2->lm_addr) || (lm1->lm_size !=
		    lm2->lm_size)) {
			res = -1;

			if (lm1->lm_addr == lm2->lm_addr && lm1->lm_size <
			    lm2->lm_size || lm1->lm_addr < lm2->lm_addr) {
				lmv = &lm1;
				ch = '-';
			} else {
				lmv = &lm2;
				ch = '+';
			}
			OUTPUT_LABEL();
			debug("%c%p+0x%llx\n", ch, (void *)(*lmv)->lm_addr,
			    (long long)(*lmv)->lm_size);
			*lmv = (*lmv)->lm_next;
		} else {
			lm1 = lm1->lm_next;
			lm2 = lm2->lm_next;
		}
	}
	while (lm1 != NULL) {
		OUTPUT_LABEL();
		debug("%c%p+0x%llx\n", '-', (void *)lm1->lm_addr,
		    (unsigned long long)lm1->lm_size);
		lm1 = lm1->lm_next;
		res = 1;
	}
	while (lm2 != NULL) {
		OUTPUT_LABEL();
		debug("%c%p+0x%llx\n", '+', (void *)lm2->lm_addr,
		    (long long)lm2->lm_size);
		lm2 = lm2->lm_next;
		res = 1;
	}

	return (res);
#undef OUTPUT_LABEL
}
#endif /* DEBUG */
