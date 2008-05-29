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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/shm.h>
#include "filebench.h"

/* IPC Hub and Simple memory allocator */

static int shmfd;
filebench_shm_t *filebench_shm = NULL;
static pthread_mutexattr_t *mutexattr = NULL;

/*
 * Interprocess Communication mechanisms. If multiple processes
 * are used, filebench opens a shared file in memory mapped mode to hold
 * a variety of global variables and data structures. If only using
 * multiple threads, it just allocates a region of local memory. A
 * region of interprocess shared memory and a set of shared semaphores
 * are also created. Routines are provided to manage the creation,
 * destruction, and allocation of these resoures.
 */


/*
 * Locks a mutex and logs any errors.
 */
int
ipc_mutex_lock(pthread_mutex_t *mutex)
{
	int error;

	error = pthread_mutex_lock(mutex);

#ifdef HAVE_ROBUST_MUTEX
	if (error == EOWNERDEAD) {
		if (pthread_mutex_consistent_np(mutex) != 0) {
			filebench_log(LOG_FATAL, "mutex make consistent "
			    "failed: %s", strerror(error));
			return (-1);
		}
		return (0);
	}
#endif /* HAVE_ROBUST_MUTEX */

	if (error != 0) {
		filebench_log(LOG_FATAL, "mutex lock failed: %s",
		    strerror(error));
	}

	return (error);
}

/*
 * Unlocks a mutex and logs any errors.
 */
int
ipc_mutex_unlock(pthread_mutex_t *mutex)
{
	int error;

	error = pthread_mutex_unlock(mutex);

#ifdef HAVE_ROBUST_MUTEX
	if (error == EOWNERDEAD) {
		if (pthread_mutex_consistent_np(mutex) != 0) {
			filebench_log(LOG_FATAL, "mutex make consistent "
			    "failed: %s", strerror(error));
			return (-1);
		}
		return (0);
	}
#endif /* HAVE_ROBUST_MUTEX */

	if (error != 0) {
		filebench_log(LOG_FATAL, "mutex unlock failed: %s",
		    strerror(error));
	}

	return (error);
}

/*
 * On first invocation, allocates a mutex attributes structure
 * and initializes it with appropriate attributes. In all cases,
 * returns a pointer to the structure.
 */
pthread_mutexattr_t *
ipc_mutexattr(void)
{
#ifdef USE_PROCESS_MODEL
	if (mutexattr == NULL) {
		if ((mutexattr =
		    malloc(sizeof (pthread_mutexattr_t))) == NULL) {
			filebench_log(LOG_ERROR, "cannot alloc mutex attr");
			filebench_shutdown(1);
		}
#ifdef HAVE_PROCSCOPE_PTHREADS
		(void) pthread_mutexattr_init(mutexattr);
		if (pthread_mutexattr_setpshared(mutexattr,
		    PTHREAD_PROCESS_SHARED) != 0) {
			filebench_log(LOG_ERROR, "cannot set mutex attr "
			    "PROCESS_SHARED on this platform");
			filebench_shutdown(1);
		}
#ifdef HAVE_PTHREAD_MUTEXATTR_SETPROTOCOL
		if (pthread_mutexattr_setprotocol(mutexattr,
		    PTHREAD_PRIO_INHERIT) != 0) {
			filebench_log(LOG_ERROR, "cannot set mutex attr "
			    "PTHREAD_PRIO_INHERIT on this platform");
			filebench_shutdown(1);
		}
#endif /* HAVE_PTHREAD_MUTEXATTR_SETPROTOCOL */
#endif /* HAVE_PROCSCOPE_PTHREADS */
#ifdef HAVE_ROBUST_MUTEX
		if (pthread_mutexattr_setrobust_np(mutexattr,
		    PTHREAD_MUTEX_ROBUST_NP) != 0) {
			filebench_log(LOG_ERROR, "cannot set mutex attr "
			    "PTHREAD_MUTEX_ROBUST_NP on this platform");
			filebench_shutdown(1);
		}
		if (pthread_mutexattr_settype(mutexattr,
		    PTHREAD_MUTEX_ERRORCHECK) != 0) {
			filebench_log(LOG_ERROR, "cannot set mutex attr "
			    "PTHREAD_MUTEX_ERRORCHECK on this platform");
			filebench_shutdown(1);
		}
#endif /* HAVE_ROBUST_MUTEX */

	}
#endif /* USE_PROCESS_MODEL */
	return (mutexattr);
}

static pthread_condattr_t *condattr = NULL;

/*
 * On first invocation, allocates a condition variable attributes
 * structure and initializes it with appropriate attributes. In
 * all cases, returns a pointer to the structure.
 */
pthread_condattr_t *
ipc_condattr(void)
{
#ifdef USE_PROCESS_MODEL
	if (condattr == NULL) {
		if ((condattr = malloc(sizeof (pthread_condattr_t))) == NULL) {
			filebench_log(LOG_ERROR, "cannot alloc cond attr");
			filebench_shutdown(1);
		}
#ifdef HAVE_PROCSCOPE_PTHREADS
		(void) pthread_condattr_init(condattr);
		if (pthread_condattr_setpshared(condattr,
		    PTHREAD_PROCESS_SHARED) != 0) {
			filebench_log(LOG_ERROR,
			    "cannot set cond attr PROCESS_SHARED");
			filebench_shutdown(1);
		}
#endif /* HAVE_PROCSCOPE_PTHREADS */
	}
#endif /* USE_PROCESS_MODEL */
	return (condattr);
}

static pthread_rwlockattr_t *rwlockattr = NULL;

/*
 * On first invocation, allocates a readers/writers attributes
 * structure and initializes it with appropriate attributes.
 * In all cases, returns a pointer to the structure.
 */
static pthread_rwlockattr_t *
ipc_rwlockattr(void)
{
#ifdef USE_PROCESS_MODEL
	if (rwlockattr == NULL) {
		if ((rwlockattr =
		    malloc(sizeof (pthread_rwlockattr_t))) == NULL) {
			filebench_log(LOG_ERROR, "cannot alloc rwlock attr");
			filebench_shutdown(1);
		}
#ifdef HAVE_PROCSCOPE_PTHREADS
		(void) pthread_rwlockattr_init(rwlockattr);
		if (pthread_rwlockattr_setpshared(rwlockattr,
		    PTHREAD_PROCESS_SHARED) != 0) {
			filebench_log(LOG_ERROR,
			    "cannot set rwlock attr PROCESS_SHARED");
			filebench_shutdown(1);
		}
#endif /* HAVE_PROCSCOPE_PTHREADS */
	}
#endif /* USE_PROCESS_MODEL */
	return (rwlockattr);
}

char *shmpath = NULL;

/*
 * Calls semget() to get a set of shared system V semaphores.
 */
void
ipc_seminit(void)
{
	key_t key = filebench_shm->shm_semkey;
	int sys_semid;

	/* Already done? */
	if (filebench_shm->shm_sys_semid >= 0)
		return;

	if ((sys_semid = semget(key, FILEBENCH_NSEMS, IPC_CREAT |
	    S_IRUSR | S_IWUSR)) == -1) {
		filebench_log(LOG_ERROR,
		    "could not create sysv semaphore set "
		    "(need to increase sems?): %s",
		    strerror(errno));
		filebench_shutdown(1);
	}

	filebench_shm->shm_sys_semid = sys_semid;
}

/*
 * Initialize the Interprocess Communication system and its
 * associated shared memory structure. It first creates a
 * temporary file using either the mkstemp() function or the
 * tempnam() and open() functions. If the process model is in
 * use,it than sets the file large enough to hold the
 * filebench_shm and an additional Megabyte. The file is then
 * memory mapped. If the process model is not in use, it simply
 * mallocs a region of sizeof (filebench_shm_t).
 *
 * Once the shared memory region / file is created, ipc_init
 * initializes various locks pointers, and variables in the
 * shared memory. It also uses ftok() to get a shared memory
 * semaphore key for later use in allocating shared semaphores.
 */
void
ipc_init(void)
{
	filebench_shm_t *buf = malloc(MB);
	key_t key;
	caddr_t c1;
	caddr_t c2;
#ifdef HAVE_SEM_RMID
	int sys_semid;
#endif

#ifdef HAVE_MKSTEMP
	shmpath = (char *)malloc(128);
	(void) strcpy(shmpath, "/var/tmp/fbenchXXXXXX");
	shmfd = mkstemp(shmpath);
#else
	shmfd   = open(shmpath, O_CREAT | O_RDWR | O_TRUNC, 0666);
	shmpath = tempnam("/var/tmp", "fbench");
#endif	/* HAVE_MKSTEMP */

#ifdef USE_PROCESS_MODEL

	if (shmfd  < 0) {
		filebench_log(LOG_FATAL, "Cannot open shm %s: %s",
		    shmpath,
		    strerror(errno));
		exit(1);
	}

	(void) lseek(shmfd, sizeof (filebench_shm_t), SEEK_SET);
	if (write(shmfd, buf, MB) != MB) {
		filebench_log(LOG_FATAL,
		    "Cannot allocate shm: %s", strerror(errno));
		exit(1);
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	if ((filebench_shm = (filebench_shm_t *)mmap((caddr_t)0,
	    sizeof (filebench_shm_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED, shmfd, 0)) == NULL) {
		filebench_log(LOG_FATAL, "Cannot mmap shm");
		exit(1);
	}

#else
	if ((filebench_shm =
	    (filebench_shm_t *)malloc(sizeof (filebench_shm_t))) == NULL) {
		filebench_log(LOG_FATAL, "Cannot malloc shm");
		exit(1);
	}
#endif /* USE_PROCESS_MODEL */

	c1 = (caddr_t)filebench_shm;
	c2 = (caddr_t)&filebench_shm->shm_marker;

	(void) memset(filebench_shm, 0, c2 - c1);
	filebench_shm->shm_epoch = gethrtime();
	filebench_shm->shm_debug_level = LOG_VERBOSE;
	filebench_shm->shm_rmode = FILEBENCH_MODE_TIMEOUT;
	filebench_shm->shm_string_ptr = &filebench_shm->shm_strings[0];
	filebench_shm->shm_ptr = (char *)filebench_shm->shm_addr;
	filebench_shm->shm_path_ptr = &filebench_shm->shm_filesetpaths[0];

	/* Setup mutexes for object lists */
	(void) pthread_mutex_init(&filebench_shm->shm_fileset_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_procflow_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_procs_running_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_threadflow_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_flowop_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_msg_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_eventgen_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_malloc_lock,
	    ipc_mutexattr());
	(void) pthread_mutex_init(&filebench_shm->shm_ism_lock,
	    ipc_mutexattr());
	(void) pthread_cond_init(&filebench_shm->shm_eventgen_cv,
	    ipc_condattr());
	(void) pthread_rwlock_init(&filebench_shm->shm_flowop_find_lock,
	    ipc_rwlockattr());
	(void) pthread_rwlock_init(&filebench_shm->shm_run_lock,
	    ipc_rwlockattr());
	(void) pthread_rwlock_rdlock(&filebench_shm->shm_run_lock);

	(void) ipc_mutex_lock(&filebench_shm->shm_ism_lock);

	/* Create semaphore */
	if ((key = ftok(shmpath, 1)) < 0) {
		filebench_log(LOG_ERROR, "cannot create sem: %s",
		    strerror(errno));
		exit(1);
	}

#ifdef HAVE_SEM_RMID
	if ((sys_semid = semget(key, 0, 0)) != -1)
		(void) semctl(sys_semid, 0, IPC_RMID);
#endif

	filebench_shm->shm_semkey = key;
	filebench_shm->shm_sys_semid = -1;
	filebench_shm->shm_log_fd = -1;
	filebench_shm->shm_dump_fd = -1;
	filebench_shm->shm_eventgen_hz = 0;
	filebench_shm->shm_id = -1;

	free(buf);
}

/*
 * If compiled to use process model, just unlinks the shmpath.
 * Otherwise a no-op.
 */
void
ipc_fini(void)
{
#ifdef USE_PROCESS_MODEL
	(void) unlink(shmpath);
#endif /* USE_PROCESS_MODEL */

#ifdef HAVE_SEM_RMID
	if (filebench_shm->shm_sys_semid != -1) {
		(void) semctl(filebench_shm->shm_sys_semid, 0, IPC_RMID);
		filebench_shm->shm_sys_semid = -1;
	}
#endif
}

/*
 * Attach to shared memory. Used by worker processes to open
 * and mmap the shared memory region. If successful, it
 * initializes the worker process' filebench_shm to point to
 * the region and returns 0. Otherwise it returns -1.
 */
int
ipc_attach(caddr_t shmaddr)
{
	if ((shmfd = open(shmpath, O_RDWR, 0666)) < 0) {
		filebench_log(LOG_ERROR, "Cannot open shm");
		return (-1);
	}

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	if ((filebench_shm = (filebench_shm_t *)mmap(shmaddr,
	    sizeof (filebench_shm_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_FIXED, shmfd, 0)) == NULL) {
		filebench_log(LOG_ERROR, "Cannot mmap shm");
		return (-1);
	}

	filebench_log(LOG_DEBUG_IMPL, "addr = %zx", filebench_shm);

	return (0);
}

static int filebench_sizes[] = {
	FILEBENCH_NPROCFLOWS,		/* number of procflows */
	FILEBENCH_NTHREADFLOWS,		/* number of threadflows */
	FILEBENCH_NFLOWOPS,		/* number of flowops */
	(FILEBENCH_NVARS * 2),		/* number of attribute value dscrs */
	FILEBENCH_NVARS,		/* number of variables */
	FILEBENCH_NFILESETS,		/* number of filesets */
	FILEBENCH_NFILESETENTRIES,	/* number of fileset entries */
	FILEBENCH_NRANDDISTS};		/* number of random distributions */

/*
 * Allocates filebench objects from pre allocated region of
 * shareable memory. The memory region is partitioned into sets
 * of objects during initialization. This routine scans for
 * the first unallocated object of type "type" in the set of
 * available objects, and makes it as allocated. The routine
 * returns a pointer to the object, or NULL if all objects have
 * been allocated.
 */
void *
ipc_malloc(int type)
{
	int i;
	int max = filebench_sizes[type];
	int start_idx = filebench_shm->shm_lastbitmapindex[type];

	(void) ipc_mutex_lock(&filebench_shm->shm_malloc_lock);

	i = start_idx;
	do {
		i++;
		if (i >= max)
			i = 0;

		if (filebench_shm->shm_bitmap[type][i] == 0)
			break;

	} while (i != start_idx);

	if (i == start_idx) {
		filebench_log(LOG_ERROR, "Out of shared memory (%d)!", type);
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return (NULL);
	}

	filebench_shm->shm_bitmap[type][i] = 1;
	filebench_shm->shm_lastbitmapindex[type] = i;

	switch (type) {
	case FILEBENCH_FILESET:
		(void) memset((char *)&filebench_shm->shm_fileset[i], 0,
		    sizeof (fileset_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_fileset[i]);

	case FILEBENCH_FILESETENTRY:
		(void) memset((char *)&filebench_shm->shm_filesetentry[i], 0,
		    sizeof (filesetentry_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_filesetentry[i]);

	case FILEBENCH_PROCFLOW:
		(void) memset((char *)&filebench_shm->shm_procflow[i], 0,
		    sizeof (procflow_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_procflow[i]);

	case FILEBENCH_THREADFLOW:
		(void) memset((char *)&filebench_shm->shm_threadflow[i], 0,
		    sizeof (threadflow_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_threadflow[i]);

	case FILEBENCH_FLOWOP:
		(void) memset((char *)&filebench_shm->shm_flowop[i], 0,
		    sizeof (flowop_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_flowop[i]);

	case FILEBENCH_AVD:
		filebench_shm->shm_avd_ptrs[i].avd_type = AVD_INVALID;
		filebench_shm->shm_avd_ptrs[i].avd_val.varptr = NULL;
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_avd_ptrs[i]);

	case FILEBENCH_VARIABLE:
		(void) memset((char *)&filebench_shm->shm_var[i], 0,
		    sizeof (var_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_var[i]);

	case FILEBENCH_RANDDIST:
		(void) memset((char *)&filebench_shm->shm_randdist[i], 0,
		    sizeof (randdist_t));
		(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
		return ((char *)&filebench_shm->shm_randdist[i]);
	}

	filebench_log(LOG_ERROR, "Attempt to ipc_malloc unknown type (%d)!",
	    type);
	return (NULL);
}

/*
 * Frees a filebench object of type "type" at the location
 * pointed to by "addr". It uses the type and address to
 * calculate which object is being freed, and clears its
 * allocation map entry.
 */
void
ipc_free(int type, char *addr)
{
	int item;
	caddr_t base;
	size_t offset;
	size_t size;

	if (addr == NULL) {
		filebench_log(LOG_ERROR, "Freeing type %d %zx", type, addr);
		return;
	}

	switch (type) {

	case FILEBENCH_FILESET:
		base = (caddr_t)&filebench_shm->shm_fileset[0];
		size = sizeof (fileset_t);
		break;

	case FILEBENCH_FILESETENTRY:
		base = (caddr_t)&filebench_shm->shm_filesetentry[0];
		size = sizeof (filesetentry_t);
		break;

	case FILEBENCH_PROCFLOW:
		base = (caddr_t)&filebench_shm->shm_procflow[0];
		size = sizeof (procflow_t);
		break;

	case FILEBENCH_THREADFLOW:
		base = (caddr_t)&filebench_shm->shm_threadflow[0];
		size = sizeof (threadflow_t);
		break;

	case FILEBENCH_FLOWOP:
		base = (caddr_t)&filebench_shm->shm_flowop[0];
		size = sizeof (flowop_t);
		break;

	case FILEBENCH_AVD:
		base = (caddr_t)&filebench_shm->shm_avd_ptrs[0];
		size = sizeof (avd_t);
		break;

	case FILEBENCH_VARIABLE:
		base = (caddr_t)&filebench_shm->shm_var[0];
		size = sizeof (var_t);
		break;

	case FILEBENCH_RANDDIST:
		base = (caddr_t)&filebench_shm->shm_randdist[0];
		size = sizeof (randdist_t);
		break;
	}

	offset = ((size_t)addr - (size_t)base);
	item = offset / size;

	(void) ipc_mutex_lock(&filebench_shm->shm_malloc_lock);
	filebench_shm->shm_bitmap[type][item] = 0;
	(void) ipc_mutex_unlock(&filebench_shm->shm_malloc_lock);
}

/*
 * Allocate a string from filebench string memory. The length
 * of the allocated string is the same as the length of the
 * supplied string "string", and the contents of string are
 * copied to the newly allocated string.
 */
char *
ipc_stralloc(char *string)
{
	char *allocstr = filebench_shm->shm_string_ptr;

	filebench_shm->shm_string_ptr += strlen(string) + 1;

	if ((filebench_shm->shm_string_ptr - &filebench_shm->shm_strings[0]) >
	    FILEBENCH_STRINGMEMORY) {
		filebench_log(LOG_ERROR, "Out of ipc string memory");
		return (NULL);
	}

	(void) strncpy(allocstr, string, strlen(string));

	return (allocstr);
}

/*
 * Allocate a path string from filebench path string memory.
 * Specifically used for allocating fileset paths. The length
 * of the allocated path string is the same as the length of
 * the supplied path string "path", and the contents of path
 * are copied to the newly allocated path string. Checks for
 * out-of-path-string-memory condition and returns NULL if so.
 * Otherwise it returns a pointer to the newly allocated path
 * string.
 */
char *
ipc_pathalloc(char *path)
{
	char *allocpath = filebench_shm->shm_path_ptr;

	filebench_shm->shm_path_ptr += strlen(path) + 1;

	if ((filebench_shm->shm_path_ptr -
	    &filebench_shm->shm_filesetpaths[0]) >
	    FILEBENCH_FILESETPATHMEMORY) {
		filebench_log(LOG_ERROR, "Out of fileset path memory");
		return (NULL);
	}

	(void) strncpy(allocpath, path, strlen(path));

	return (allocpath);
}

/*
 * This is a limited functionality deallocator for path
 * strings - it can only free all path strings at once,
 * in order to avoid fragmentation.
 */
void
ipc_freepaths(void)
{
	filebench_shm->shm_path_ptr = &filebench_shm->shm_filesetpaths[0];
}

/*
 * Allocates a semid from the table of semids for pre intialized
 * semaphores. Searches for the first available semaphore, and
 * sets the entry in the table to "1" to indicate allocation.
 * Returns the allocated semid. Stops the run if all semaphores
 * are already in use.
 */
int
ipc_semidalloc(void)
{
	int semid;

	for (semid = 0; filebench_shm->shm_semids[semid] == 1; semid++)
		;
	if (semid == FILEBENCH_NSEMS) {
		filebench_log(LOG_ERROR,
		    "Out of semaphores, increase system tunable limit");
		filebench_shutdown(1);
	}
	filebench_shm->shm_semids[semid] = 1;
	return (semid);
}

/*
 * Frees up the supplied semid by seting its position in the
 * allocation table to "0".
 */
void
ipc_semidfree(int semid)
{
	filebench_shm->shm_semids[semid] = 0;
}

/*
 * Create a pool of shared memory to fit the per-thread
 * allocations. Uses shmget() to create a shared memory region
 * of size "size", attaches to it using shmat(), and stores
 * the returned address of the region in filebench_shm->shm_addr.
 * The pool is only created on the first call. The routine
 * returns 0 if successful or the pool already exists,
 * -1 otherwise.
 */
int
ipc_ismcreate(size_t size)
{
#ifdef HAVE_SHM_SHARE_MMU
	int flag = SHM_SHARE_MMU;
#else
	int flag = 0;
#endif /* HAVE_SHM_SHARE_MMU */

	/* Already done? */
	if (filebench_shm->shm_id != -1)
		return (0);

	filebench_log(LOG_VERBOSE,
	    "Creating %zd bytes of ISM Shared Memory...", size);

	if ((filebench_shm->shm_id =
	    shmget(0, size, IPC_CREAT | 0666)) == -1) {
		filebench_log(LOG_ERROR,
		    "Failed to create %zd bytes of ISM shared memory", size);
		return (-1);
	}

	if ((filebench_shm->shm_addr = (caddr_t)shmat(filebench_shm->shm_id,
	    0, flag)) == (void *)-1) {
		filebench_log(LOG_ERROR,
		    "Failed to attach %zd bytes of created ISM shared memory",
		    size);
		return (-1);
	}

	filebench_shm->shm_ptr = (char *)filebench_shm->shm_addr;

	filebench_log(LOG_VERBOSE,
	    "Allocated %zd bytes of ISM Shared Memory... at %zx",
	    size, filebench_shm->shm_addr);

	/* Locked until allocated to block allocs */
	(void) ipc_mutex_unlock(&filebench_shm->shm_ism_lock);

	return (0);
}

/* Per addr space ism */
static int ism_attached = 0;

/*
 * Attach to interprocess shared memory. If already attached
 * just return, otherwise use shmat() to attached to the region
 * with ID of filebench_shm->shm_id. Returns -1 if shmat()
 * fails, otherwise 0.
 */
static int
ipc_ismattach(void)
{
#ifdef HAVE_SHM_SHARE_MMU
	int flag = SHM_SHARE_MMU;
#else
	int flag = 0;
#endif /* HAVE_SHM_SHARE_MMU */


	if (ism_attached)
		return (0);

	/* Does it exist? */
	if (filebench_shm->shm_id == 999)
		return (0);

	if (shmat(filebench_shm->shm_id, filebench_shm->shm_addr,
	    flag) == NULL)
		return (-1);

	ism_attached = 1;

	return (0);
}

/*
 * Allocate from interprocess shared memory. Attaches to ism
 * if necessary, then allocates "size" bytes, updates allocation
 * information and returns a pointer to the allocated memory.
 */
/*
 * XXX No check is made for out-of-memory condition
 */
char *
ipc_ismmalloc(size_t size)
{
	char *allocstr;

	(void) ipc_mutex_lock(&filebench_shm->shm_ism_lock);

	/* Map in shared memory */
	(void) ipc_ismattach();

	allocstr = filebench_shm->shm_ptr;

	filebench_shm->shm_ptr += size;
	filebench_shm->shm_allocated += size;

	(void) ipc_mutex_unlock(&filebench_shm->shm_ism_lock);

	return (allocstr);
}

/*
 * Deletes shared memory region and resets shared memory region
 * information in filebench_shm.
 */
void
ipc_ismdelete(void)
{
	if (filebench_shm->shm_id == -1)
		return;

	filebench_log(LOG_VERBOSE, "Deleting ISM...");

	(void) ipc_mutex_lock(&filebench_shm->shm_ism_lock);
#ifdef HAVE_SEM_RMID
	(void) shmctl(filebench_shm->shm_id, IPC_RMID, 0);
#endif
	filebench_shm->shm_ptr = (char *)filebench_shm->shm_addr;
	filebench_shm->shm_id = -1;
	filebench_shm->shm_allocated = 0;
	(void) ipc_mutex_unlock(&filebench_shm->shm_ism_lock);
}
