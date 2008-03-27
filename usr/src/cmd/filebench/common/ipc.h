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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FB_IPC_H
#define	_FB_IPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"
#include <pthread.h>

#include "procflow.h"
#include "threadflow.h"
#include "fileset.h"
#include "flowop.h"
#include "fb_random.h"
#include "filebench.h"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef USE_PROCESS_MODEL
#define	FILEBENCH_MEMSIZE 4096
#else
#define	FILEBENCH_MEMSIZE 2048
#endif /* USE_PROCESS_MODEL */

#define	FILEBENCH_NFILESETS FILEBENCH_MEMSIZE
#define	FILEBENCH_NFILESETENTRIES (1024 * 1024)
#define	FILEBENCH_NPROCFLOWS FILEBENCH_MEMSIZE
#define	FILEBENCH_NTHREADFLOWS (64 * FILEBENCH_MEMSIZE)
#define	FILEBENCH_NFLOWOPS (64 * FILEBENCH_MEMSIZE)
#define	FILEBENCH_NVARS FILEBENCH_MEMSIZE
#define	FILEBENCH_NRANDDISTS (FILEBENCH_MEMSIZE/4)
#define	FILEBENCH_FILESETPATHMEMORY (FILEBENCH_NFILESETENTRIES*FSE_MAXPATHLEN)
#define	FILEBENCH_STRINGMEMORY (FILEBENCH_NVARS * 128)
#define	FILEBENCH_MAXBITMAP FILEBENCH_NFILESETENTRIES

#define	FILEBENCH_PROCFLOW	0
#define	FILEBENCH_THREADFLOW	1
#define	FILEBENCH_FLOWOP	2
#define	FILEBENCH_AVD		3
#define	FILEBENCH_VARIABLE	4
#define	FILEBENCH_FILESET	5
#define	FILEBENCH_FILESETENTRY	6
#define	FILEBENCH_RANDDIST	7
#define	FILEBENCH_TYPES		8

#define	FILEBENCH_NSEMS 128

#define	FILEBENCH_ABORT_ERROR  	1
#define	FILEBENCH_ABORT_DONE   	2
#define	FILEBENCH_ABORT_RSRC	3

#define	FILEBENCH_MODE_TIMEOUT	0x0
#define	FILEBENCH_MODE_Q1STDONE	0x1
#define	FILEBENCH_MODE_QALLDONE	0x2

typedef struct filebench_shm {
	pthread_mutex_t fileset_lock;
	pthread_mutex_t procflow_lock;
	pthread_mutex_t threadflow_lock;
	pthread_mutex_t flowop_lock;
	pthread_mutex_t msg_lock;
	pthread_mutex_t shm_malloc_lock;
	pthread_mutex_t shm_ism_lock;
	pthread_rwlock_t run_lock;
	pthread_rwlock_t flowop_find_lock;

	char		*shm_string_ptr;
	char		*shm_path_ptr;
	fileset_t	*filesetlist;
	flowop_t	*flowoplist;
	procflow_t	*proclist;
	var_t		*var_list;
	var_t		*var_dyn_list;
	randdist_t	*shm_rand_list;
	int		debug_level;
	hrtime_t	epoch;
	hrtime_t	shm_starttime;
	int		bequiet;
	key_t		semkey;
	int		seminit;
	int		semid_seq;
	int		utid;
	int		log_fd;
	int		dump_fd;
	char		dump_filename[MAXPATHLEN];
	pthread_mutex_t	eventgen_lock;
	pthread_cond_t	eventgen_cv;
	int		eventgen_hz;
	uint64_t	eventgen_q;
	char		fscriptname[1024];
	int		shm_id;
	size_t		shm_required;
	size_t		shm_allocated;
	caddr_t		shm_addr;
	char		*shm_ptr;
	int		shm_running;
	int		f_abort;
	int		shm_rmode;
	int		shm_1st_err;
	int		shm_bitmap[FILEBENCH_TYPES][FILEBENCH_MAXBITMAP];
	int		shm_lastbitmapindex[FILEBENCH_TYPES];

	int		shm_marker;

	fileset_t	shm_fileset[FILEBENCH_NFILESETS];
	filesetentry_t	shm_filesetentry[FILEBENCH_NFILESETENTRIES];
	char		shm_filesetpaths[FILEBENCH_FILESETPATHMEMORY];
	procflow_t	shm_procflow[FILEBENCH_NPROCFLOWS];
	threadflow_t	shm_threadflow[FILEBENCH_NTHREADFLOWS];
	flowop_t	shm_flowop[FILEBENCH_NFLOWOPS];
	var_t		shm_var[FILEBENCH_NVARS];
	randdist_t	shm_randdist[FILEBENCH_NRANDDISTS];
	struct avd	shm_avd_ptrs[FILEBENCH_NVARS * 2];
	char		shm_strings[FILEBENCH_STRINGMEMORY];
	char		semids[FILEBENCH_NSEMS];
} filebench_shm_t;

extern char *shmpath;

void ipc_init(void);
void *ipc_malloc(int type);
void ipc_free(int type, char *addr);
int ipc_attach(caddr_t shmaddr);
pthread_mutexattr_t *ipc_mutexattr(void);
pthread_condattr_t *ipc_condattr(void);
int ipc_semidalloc(void);
void ipc_semidfree(int semid);
char *ipc_stralloc(char *string);
char *ipc_pathalloc(char *string);
int ipc_mutex_lock(pthread_mutex_t *mutex);
int ipc_mutex_unlock(pthread_mutex_t *mutex);
void ipc_seminit(void);
char *ipc_ismmalloc(size_t size);
int ipc_ismcreate(size_t size);
void ipc_ismdelete(void);
void ipc_cleanup(void);

extern filebench_shm_t *filebench_shm;

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_IPC_H */
