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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PSTACK_H
#define	_PSTACK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Support functions for ISA-dependent Pstack_iter().
 */
int stack_loop(prgreg_t fp, prgreg_t **prevfpp, int *nfpp, uint_t *pfpsizep);

typedef struct {
	struct ps_prochandle *uc_proc;	/* libproc handle */
	uintptr_t *uc_addrs;		/* array of stack addresses */
	uint_t uc_nelems;		/* number of valid elements */
	uint_t uc_size;			/* actual size of array */
	uint_t uc_cached;		/* is cached in the ps_prochandle */
} uclist_t;

int load_uclist(uclist_t *ucl, const lwpstatus_t *psp);
int sort_uclist(const void *lhp, const void *rhp);
void init_uclist(uclist_t *ucl, struct ps_prochandle *P);
void free_uclist(uclist_t *ucl);
int find_uclink(uclist_t *ucl, uintptr_t addr);



#ifdef	__cplusplus
}
#endif

#endif	/* _PSTACK_H */
