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
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_FPU_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_FPU_H_

void	fpuexit(kthread_t *td);
void	fpurestore(void *);
void	fpusave(void *);

struct savefpu	*fpu_save_area_alloc(void);
void	fpu_save_area_free(struct savefpu *fsa);
void	fpu_save_area_reset(struct savefpu *fsa);

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_FPU_H_ */
