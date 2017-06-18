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

#ifndef _PRB_PROC_INT_H
#define	_PRB_PROC_INT_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Interfaces private to proc layer
 */

#include <sys/types.h>
#include <sys/syscall.h>

#include <tnf/probe.h>

#include "prb_proc.h"

/*
 * size of breakpoint instruction
 */
#if defined(__sparc)
typedef unsigned int bptsave_t;
#elif defined(__i386) || defined(__amd64)
typedef unsigned char bptsave_t;
#endif

/*
 * memory shared between parent and child when exec'ing a child.
 * child spins on "spin" member waiting for parent to set it free
 */
typedef struct shmem_msg {
	boolean_t	spin;
} shmem_msg_t;

/*
 * per /proc handle state
 */
struct prb_proc_ctl {
	int 		procfd;
	int		pid;
	uintptr_t	bptaddr;
	bptsave_t	saveinstr;	/* instruction that bpt replaced */
	boolean_t	bpt_inserted;	/* is bpt inserted ? */
	uintptr_t	dbgaddr;
};

/*
 * Declarations
 */
prb_status_t	prb_status_map(int);
prb_status_t	find_executable(const char *name, char *ret_path);

/* shared memory lock interfaces */
prb_status_t	prb_shmem_init(volatile shmem_msg_t **);
prb_status_t	prb_shmem_wait(volatile shmem_msg_t *);
prb_status_t	prb_shmem_clear(volatile shmem_msg_t *);
prb_status_t	prb_shmem_free(volatile shmem_msg_t *smp);

/* runs and stops the process to clear it out of system call */
prb_status_t	prb_proc_prstop(prb_proc_ctl_t *proc_p);

/* break point interfaces */
prb_status_t	prb_proc_tracebpt(prb_proc_ctl_t *proc_p, boolean_t bpt);
prb_status_t	prb_proc_istepbpt(prb_proc_ctl_t *proc_p);
prb_status_t	prb_proc_clrbptflt(prb_proc_ctl_t *proc_p);

/* read a string from target process */
prb_status_t	prb_proc_readstr(prb_proc_ctl_t *proc_p, uintptr_t addr,
			const char **outstr_pp);

#ifdef __cplusplus
}
#endif

#endif	/* _PRB_PROC_INT_H */
