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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _CL_SMEM_PUB_
#define	_CL_SMEM_PUB_

#ifndef _SBLK_DEFS_
#include "sblk_defs.h"
#endif


enum ipc_check {
	IPC_CHECK_KEY,
	IPC_CHECK_ID
};


int		cl_sem_attach(int semaphore_key);
int		cl_sem_create(int semaphore_key);
STATUS		cl_sem_check(enum ipc_check type, int semaphore);
BOOLEAN cl_sem_destroy(int semaphore_id);
STATUS		cl_sem_lock(int semaphore_id);
BOOLEAN cl_sem_unlock(int semaphore_id);

STATUS cl_dshm_attach(int i_dshm_key, struct dshm_id *p_dshm_id,
    char **cppw_shared_ptr, char *cp_name);
STATUS cl_dshm_build(enum dshm_build_flag build_flag,
    int i_dshm_key, int size,
    struct dshm_id *p_dshm_id, char **pp_shared_mem,
    STATUS (*build_func)(char *, void *),
    void *p_func_param, char *name);
STATUS cl_dshm_check(int i_key, char *cp_name);
STATUS cl_dshm_destroy(struct dshm_id *p_dshm_id);

int		cl_smem_attach(int shared_key, int size, char **shared);
STATUS		cl_smem_check(enum ipc_check type, int shared_mem);
int		cl_smem_create(int shared_key, int total_size, char **shared);
BOOLEAN cl_smem_destroy(int shmid);


#endif /* _CL_SMEM_PUB_ */
