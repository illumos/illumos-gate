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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Interfaces to allocate, control, and free a shared memory lock
 * XXXX Could we use a semaphore or a shared memory condition variable
 * instead ?
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "prb_proc_int.h"
#include "dbg.h"

static boolean_t getspin(volatile shmem_msg_t *smp);

/*
 * prb_shmem_init() - Allocates and initializes the shared memory region
 */
prb_status_t
prb_shmem_init(volatile shmem_msg_t **ret_val)
{
	int		shmem_fd;
	volatile	shmem_msg_t *smp;

	DBG_TNF_PROBE_0(prb_shmem_init_1, "libtnfctl", "sunw%verbosity 2");

	shmem_fd = open("/dev/zero", O_RDWR);
	if (shmem_fd == -1) {
		DBG((void) fprintf(stderr, "couldn't open \"/dev/zero\""));
		return (prb_status_map(errno));
	}
	/*LINTED pointer cast may result in improper alignment*/
	smp = (shmem_msg_t *) mmap(0, sizeof (struct shmem_msg),
			PROT_READ | PROT_WRITE, MAP_SHARED,
			shmem_fd, 0);
	if (smp == (struct shmem_msg *) - 1) {
		DBG((void) fprintf(stderr, "couldn't mmap \"/dev/zero\""));
		return (prb_status_map(errno));
	}
	(void) close(shmem_fd);

	/* sets the shared memory region to cause waiting */
	smp->spin = B_TRUE;

	*ret_val = smp;

	return (PRB_STATUS_OK);
}

/*
 * prb_shmem_wait() - spins until the shared memory flag is cleared
 */
static boolean_t
getspin(volatile shmem_msg_t *smp)
{
	return (smp->spin);
}

prb_status_t
prb_shmem_wait(volatile shmem_msg_t *smp)
{
	DBG_TNF_PROBE_0(prb_shmem_wait_start, "libtnfctl",
		"sunw%verbosity 2; start prb_shmem_wait");

	while (getspin(smp));

	DBG_TNF_PROBE_0(prb_shmem_wait_end, "libtnfctl",
		"sunw%verbosity 2; end prb_shmem_wait");

	return (PRB_STATUS_OK);

}


/*
 * prb_shmem_clear() - clears the shared memory flag and allows waiters to
 * proceed.
 */
prb_status_t
prb_shmem_clear(volatile shmem_msg_t *smp)
{
	DBG_TNF_PROBE_0(prb_shmem_clear_1, "libtnfctl", "sunw%verbosity 2");

	smp->spin = B_FALSE;

	return (PRB_STATUS_OK);
}

/*
 * prb_shmem_free() - Unmaps the shared memory region.
 */
prb_status_t
prb_shmem_free(volatile shmem_msg_t *smp)
{
	DBG_TNF_PROBE_0(prb_shmem_free_1, "libtnfctl", "sunw%verbosity 2");

	if (munmap((caddr_t) smp, sizeof (struct shmem_msg)) != 0) {
		DBG((void) fprintf(stderr, "couldn't munmap shared memory\n"));
		return (prb_status_map(errno));
	}

	return (PRB_STATUS_OK);
}
