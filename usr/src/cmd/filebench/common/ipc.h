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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FB_IPC_H
#define	_FB_IPC_H

#include "config.h"
#include <pthread.h>

#include "procflow.h"
#include "threadflow.h"
#include "fileset.h"
#include "flowop.h"
#include "fb_random.h"
#include "fsplug.h"
#include "filebench.h"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef USE_PROCESS_MODEL
#define	FILEBENCH_MEMSIZE 4096
#else
#define	FILEBENCH_MEMSIZE 2048
#endif /* USE_PROCESS_MODEL */

/* Mutex Priority Inheritance and Robustness flags */
#define	IPC_MUTEX_NORMAL	0x0
#define	IPC_MUTEX_PRIORITY	0x1
#define	IPC_MUTEX_ROBUST	0x2
#define	IPC_MUTEX_PRI_ROB	0x3
#define	IPC_NUM_MUTEX_ATTRS	4

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
	/*
	 * All state down to shm_marker are set to zero during filebench
	 * initialization
	 */

	/*
	 * list of defined filesets and related locks.
	 */
	fileset_t	*shm_filesetlist; /* list of defined filesets */
	pthread_mutex_t shm_fileset_lock; /* protects access to list */

	/*
	 * parallel file allocation  control. Restricts number of spawned
	 * allocation threads and allows waiting for allocation to finish.
	 */
	pthread_cond_t	shm_fsparalloc_cv;    /* cv to wait for alloc threads */
	int		shm_fsparalloc_count; /* active alloc thread count */
	pthread_mutex_t	shm_fsparalloc_lock;  /* lock to protect count */

	/*
	 * Procflow and process state
	 */
	procflow_t	*shm_proclist;	   /* list of defined procflows */
	pthread_mutex_t shm_procflow_lock; /* protects shm_proclist */
	int		shm_procs_running; /* count of running processes */
	pthread_mutex_t shm_procs_running_lock;	/* protects shm_procs_running */
	int		shm_f_abort;	/* stop the run NOW! */
	pthread_rwlock_t shm_run_lock;	/* used as barrier to sync run */
#ifdef USE_PROCESS_MODEL
	pthread_cond_t  shm_procflow_procs_cv;	/* pauses procflow_init till */
#endif						/* all procflows are created */

	/*
	 * flowop state
	 */
	flowop_t	*shm_flowoplist;	/* list of defined flowops */
	pthread_mutex_t shm_flowop_lock;	/* protects flowoplist */
	pthread_rwlock_t shm_flowop_find_lock;	/* prevents flowop_find() */
					    /* during initial flowop creation */

	/*
	 * lists related to variables
	 */

	var_t		*shm_var_list;	   /* normal variables */
	var_t		*shm_var_dyn_list; /* special system variables */
	var_t		*shm_var_loc_list; /* variables local to comp flowops */
	randdist_t	*shm_rand_list;	   /* random variables */

	/*
	 * log and statistics dumping controls and state
	 */
	int		shm_debug_level;
	int		shm_bequiet;	/* pause run while collecting stats */
	int		shm_log_fd;	/* log file descriptor */
	int		shm_dump_fd;	/* dump file descriptor */
	char		shm_dump_filename[MAXPATHLEN];

	/*
	 * Event generator state
	 */
	avd_t		shm_eventgen_hz;   /* number of events per sec. */
	uint64_t	shm_eventgen_q;    /* count of unclaimed events */
	pthread_mutex_t	shm_eventgen_lock; /* lock protecting count */
	pthread_cond_t	shm_eventgen_cv;   /* cv to wait on for more events */

	/*
	 * System 5 semaphore state
	 */
	key_t		shm_semkey;
	int		shm_sys_semid;
	char		shm_semids[FILEBENCH_NSEMS];

	/*
	 * Misc. pointers and state
	 */
	char		shm_fscriptname[1024];
	int		shm_id;
	int		shm_rmode;
	int		shm_1st_err;
	pthread_mutex_t shm_threadflow_lock;
	pthread_mutex_t shm_msg_lock;
	pthread_mutexattr_t shm_mutexattr[IPC_NUM_MUTEX_ATTRS];
	char		*shm_string_ptr;
	char		*shm_path_ptr;
	hrtime_t	shm_epoch;
	hrtime_t	shm_starttime;
	int		shm_utid;

	/*
	 * Shared memory allocation control
	 */
	pthread_mutex_t shm_malloc_lock;
	pthread_mutex_t shm_ism_lock;
	int		shm_bitmap[FILEBENCH_TYPES][FILEBENCH_MAXBITMAP];
	int		shm_lastbitmapindex[FILEBENCH_TYPES];
	size_t		shm_required;
	size_t		shm_allocated;
	caddr_t		shm_addr;
	char		*shm_ptr;

	/*
	 * Type of plug-in file system client to use. Defaults to
	 * local file system, which is type "0".
	 */
	fb_plugin_type_t shm_filesys_type;

	/*
	 * end of pre-zeroed data
	 */
	int		shm_marker;

	/*
	 * actual storage for shared entities.
	 * These are not zeroed during initialization
	 */
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
} filebench_shm_t;

extern char *shmpath;

void ipc_init(void);
void *ipc_malloc(int type);
void ipc_free(int type, char *addr);
int ipc_attach(caddr_t shmaddr);
pthread_mutexattr_t *ipc_mutexattr(int);
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
void ipc_fini(void);

extern filebench_shm_t *filebench_shm;

#ifdef	__cplusplus
}
#endif

#endif	/* _FB_IPC_H */
