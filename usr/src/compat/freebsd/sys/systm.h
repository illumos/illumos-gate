/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_SYS_SYSTM_H_
#define	_COMPAT_FREEBSD_SYS_SYSTM_H_

#include <machine/atomic.h>
#include <machine/cpufunc.h>
#include <sys/callout.h>
#include <sys/queue.h>

struct mtx;

#define	KASSERT(exp,msg) do {						\
	if (!(exp))							\
		panic msg;						\
} while (0)

void	critical_enter(void);
void	critical_exit(void);

struct unrhdr *new_unrhdr(int low, int high, struct mtx *mutex);
void delete_unrhdr(struct unrhdr *uh);
int alloc_unr(struct unrhdr *uh);
void free_unr(struct unrhdr *uh, u_int item);

#include <sys/libkern.h>

#include_next <sys/systm.h>
#include <sys/cmn_err.h>

#endif	/* _COMPAT_FREEBSD_SYS_SYSTM_H_ */
