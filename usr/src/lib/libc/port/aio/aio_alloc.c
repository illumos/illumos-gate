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

#include "lint.h"
#include "thr_uberdata.h"
#include "asyncio.h"

/*
 * The aio subsystem memory allocation strategy:
 *
 * For each of the structure types we wish to allocate/free
 * (aio_worker_t, aio_req_t, aio_lio_t), we use mmap() to allocate
 * chunks of memory which are then subdivided into individual
 * elements which are put into a free list from which allocations
 * are made and to which frees are returned.
 *
 * Chunks start small (8 Kbytes) and get larger (size doubling)
 * as more chunks are needed.  This keeps memory usage small for
 * light use and fragmentation small for heavy use.
 *
 * Chunks are never unmapped except as an aftermath of fork()
 * in the child process, when they are all unmapped (because
 * all of the worker threads disappear in the child).
 */

#define	INITIAL_CHUNKSIZE	(8 * 1024)

/*
 * The header structure for each chunk.
 * A pointer and a size_t ensures proper alignment for whatever follows.
 */
typedef struct chunk {
	struct chunk	*chunk_next;	/* linked list */
	size_t		chunk_size;	/* size of this chunk */
} chunk_t;

chunk_t *chunk_list = NULL;		/* list of all chunks */
mutex_t chunk_lock = DEFAULTMUTEX;

chunk_t *
chunk_alloc(size_t size)
{
	chunk_t *chp = NULL;
	void *ptr;

	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, (off_t)0);
	if (ptr != MAP_FAILED) {
		lmutex_lock(&chunk_lock);
		chp = ptr;
		chp->chunk_next = chunk_list;
		chunk_list = chp;
		chp->chunk_size = size;
		lmutex_unlock(&chunk_lock);
	}

	return (chp);
}

aio_worker_t *worker_freelist = NULL;	/* free list of worker structures */
aio_worker_t *worker_freelast = NULL;
size_t worker_chunksize = 0;
mutex_t worker_lock = DEFAULTMUTEX;

/*
 * Allocate a worker control block.
 */
aio_worker_t *
_aio_worker_alloc(void)
{
	aio_worker_t *aiowp;
	chunk_t *chp;
	size_t chunksize;
	int nelem;
	int i;

	lmutex_lock(&worker_lock);
	if ((aiowp = worker_freelist) == NULL) {
		if ((chunksize = 2 * worker_chunksize) == 0)
			chunksize = INITIAL_CHUNKSIZE;
		if ((chp = chunk_alloc(chunksize)) == NULL) {
			lmutex_unlock(&worker_lock);
			return (NULL);
		}
		worker_chunksize = chunksize;
		worker_freelist = (aio_worker_t *)(uintptr_t)(chp + 1);
		nelem = (chunksize - sizeof (chunk_t)) / sizeof (aio_worker_t);
		for (i = 0, aiowp = worker_freelist; i < nelem; i++, aiowp++)
			aiowp->work_forw = aiowp + 1;
		worker_freelast = aiowp - 1;
		worker_freelast->work_forw = NULL;
		aiowp = worker_freelist;
	}
	if ((worker_freelist = aiowp->work_forw) == NULL)
		worker_freelast = NULL;
	lmutex_unlock(&worker_lock);

	aiowp->work_forw = NULL;
	(void) mutex_init(&aiowp->work_qlock1, USYNC_THREAD, NULL);
	(void) cond_init(&aiowp->work_idle_cv, USYNC_THREAD, NULL);

	return (aiowp);
}

/*
 * Free a worker control block.
 * Declared with void *arg so it can be a pthread_key_create() destructor.
 */
void
_aio_worker_free(void *arg)
{
	aio_worker_t *aiowp = arg;

	(void) mutex_destroy(&aiowp->work_qlock1);
	(void) cond_destroy(&aiowp->work_idle_cv);
	(void) memset(aiowp, 0, sizeof (*aiowp));

	lmutex_lock(&worker_lock);
	if (worker_freelast == NULL) {
		worker_freelist = worker_freelast = aiowp;
	} else {
		worker_freelast->work_forw = aiowp;
		worker_freelast = aiowp;
	}
	lmutex_unlock(&worker_lock);
}

aio_req_t *_aio_freelist = NULL;	/* free list of request structures */
aio_req_t *_aio_freelast = NULL;
size_t request_chunksize = 0;
int _aio_freelist_cnt = 0;
int _aio_allocated_cnt = 0;
mutex_t __aio_cache_lock = DEFAULTMUTEX;

/*
 * Allocate an aio request structure.
 */
aio_req_t *
_aio_req_alloc(void)
{
	aio_req_t *reqp;
	chunk_t *chp;
	size_t chunksize;
	int nelem;
	int i;

	lmutex_lock(&__aio_cache_lock);
	if ((reqp = _aio_freelist) == NULL) {
		if ((chunksize = 2 * request_chunksize) == 0)
			chunksize = INITIAL_CHUNKSIZE;
		if ((chp = chunk_alloc(chunksize)) == NULL) {
			lmutex_unlock(&__aio_cache_lock);
			return (NULL);
		}
		request_chunksize = chunksize;
		_aio_freelist = (aio_req_t *)(uintptr_t)(chp + 1);
		nelem = (chunksize - sizeof (chunk_t)) / sizeof (aio_req_t);
		for (i = 0, reqp = _aio_freelist; i < nelem; i++, reqp++) {
			reqp->req_state = AIO_REQ_FREE;
			reqp->req_link = reqp + 1;
		}
		_aio_freelast = reqp - 1;
		_aio_freelast->req_link = NULL;
		_aio_freelist_cnt = nelem;
		reqp = _aio_freelist;
	}
	if ((_aio_freelist = reqp->req_link) == NULL)
		_aio_freelast = NULL;
	_aio_freelist_cnt--;
	_aio_allocated_cnt++;
	lmutex_unlock(&__aio_cache_lock);

	ASSERT(reqp->req_state == AIO_REQ_FREE);
	reqp->req_state = 0;
	reqp->req_link = NULL;
	reqp->req_sigevent.sigev_notify = SIGEV_NONE;

	return (reqp);
}

/*
 * Free an aio request structure.
 */
void
_aio_req_free(aio_req_t *reqp)
{
	ASSERT(reqp->req_state != AIO_REQ_FREE &&
	    reqp->req_state != AIO_REQ_DONEQ);
	(void) memset(reqp, 0, sizeof (*reqp));
	reqp->req_state = AIO_REQ_FREE;

	lmutex_lock(&__aio_cache_lock);
	if (_aio_freelast == NULL) {
		_aio_freelist = _aio_freelast = reqp;
	} else {
		_aio_freelast->req_link = reqp;
		_aio_freelast = reqp;
	}
	_aio_freelist_cnt++;
	_aio_allocated_cnt--;
	lmutex_unlock(&__aio_cache_lock);
}

aio_lio_t *_lio_head_freelist = NULL;	/* free list of lio head structures */
aio_lio_t *_lio_head_freelast = NULL;
size_t lio_head_chunksize = 0;
int _lio_alloc = 0;
int _lio_free = 0;
mutex_t __lio_mutex = DEFAULTMUTEX;

/*
 * Allocate a listio head structure.
 */
aio_lio_t *
_aio_lio_alloc(void)
{
	aio_lio_t *head;
	chunk_t *chp;
	size_t chunksize;
	int nelem;
	int i;

	lmutex_lock(&__lio_mutex);
	if ((head = _lio_head_freelist) == NULL) {
		if ((chunksize = 2 * lio_head_chunksize) == 0)
			chunksize = INITIAL_CHUNKSIZE;
		if ((chp = chunk_alloc(chunksize)) == NULL) {
			lmutex_unlock(&__lio_mutex);
			return (NULL);
		}
		lio_head_chunksize = chunksize;
		_lio_head_freelist = (aio_lio_t *)(uintptr_t)(chp + 1);
		nelem = (chunksize - sizeof (chunk_t)) / sizeof (aio_lio_t);
		for (i = 0, head = _lio_head_freelist; i < nelem; i++, head++)
			head->lio_next = head + 1;
		_lio_head_freelast = head - 1;
		_lio_head_freelast->lio_next = NULL;
		_lio_alloc += nelem;
		_lio_free = nelem;
		head = _lio_head_freelist;
	}
	if ((_lio_head_freelist = head->lio_next) == NULL)
		_lio_head_freelast = NULL;
	_lio_free--;
	lmutex_unlock(&__lio_mutex);

	ASSERT(head->lio_nent == 0 && head->lio_refcnt == 0);
	head->lio_next = NULL;
	head->lio_port = -1;
	(void) mutex_init(&head->lio_mutex, USYNC_THREAD, NULL);
	(void) cond_init(&head->lio_cond_cv, USYNC_THREAD, NULL);

	return (head);
}

/*
 * Free a listio head structure.
 */
void
_aio_lio_free(aio_lio_t *head)
{
	ASSERT(head->lio_nent == 0 && head->lio_refcnt == 0);
	(void) mutex_destroy(&head->lio_mutex);
	(void) cond_destroy(&head->lio_cond_cv);
	(void) memset(head, 0, sizeof (*head));

	lmutex_lock(&__lio_mutex);
	if (_lio_head_freelast == NULL) {
		_lio_head_freelist = _lio_head_freelast = head;
	} else {
		_lio_head_freelast->lio_next = head;
		_lio_head_freelast = head;
	}
	_lio_free++;
	lmutex_unlock(&__lio_mutex);
}

void
postfork1_child_aio(void)
{
	chunk_t *chp;

	/*
	 * All of the workers are gone; free their structures.
	 */
	if (_kaio_supported != NULL) {
		(void) munmap((void *)_kaio_supported,
		    MAX_KAIO_FDARRAY_SIZE * sizeof (uint32_t));
		_kaio_supported = NULL;
	}
	if (_aio_hash != NULL) {
		(void) munmap((void *)_aio_hash, HASHSZ * sizeof (aio_hash_t));
		_aio_hash = NULL;
	}
	for (chp = chunk_list; chp != NULL; chp = chunk_list) {
		chunk_list = chp->chunk_next;
		(void) munmap((void *)chp, chp->chunk_size);
	}

	/*
	 * Reinitialize global variables
	 */

	worker_freelist = NULL;
	worker_freelast = NULL;
	worker_chunksize = 0;
	(void) mutex_init(&worker_lock, USYNC_THREAD, NULL);

	_aio_freelist = NULL;
	_aio_freelast = NULL;
	request_chunksize = 0;
	_aio_freelist_cnt = 0;
	_aio_allocated_cnt = 0;
	(void) mutex_init(&__aio_cache_lock, USYNC_THREAD, NULL);

	_lio_head_freelist = NULL;
	_lio_head_freelast = NULL;
	lio_head_chunksize = 0;
	_lio_alloc = 0;
	_lio_free = 0;
	(void) mutex_init(&__lio_mutex, USYNC_THREAD, NULL);

	(void) mutex_init(&__aio_initlock, USYNC_THREAD, NULL);
	(void) cond_init(&__aio_initcv, USYNC_THREAD, NULL);
	__aio_initbusy = 0;

	(void) mutex_init(&__aio_mutex, USYNC_THREAD, NULL);
	(void) cond_init(&_aio_iowait_cv, USYNC_THREAD, NULL);
	(void) cond_init(&_aio_waitn_cv, USYNC_THREAD, NULL);

	_kaio_ok = 0;
	__uaio_ok = 0;

	_kaiowp = NULL;

	__workers_rw = NULL;
	__nextworker_rw = NULL;
	__rw_workerscnt = 0;

	__workers_no = NULL;
	__nextworker_no = NULL;
	__no_workerscnt = 0;

	_aio_worker_cnt = 0;

	_aio_done_head = NULL;
	_aio_done_tail = NULL;
	_aio_donecnt = 0;

	_aio_doneq = NULL;
	_aio_doneq_cnt = 0;

	_aio_waitncnt = 0;
	_aio_outstand_cnt = 0;
	_kaio_outstand_cnt = 0;
	_aio_req_done_cnt = 0;
	_aio_kernel_suspend = 0;
	_aio_suscv_cnt = 0;

	_aiowait_flag = 0;
	_aio_flags = 0;
}

#define	DISPLAY(var)	\
	(void) fprintf(stderr, #var "\t= %d\n", var)

static void
_aio_exit_info(void)
{
	if ((_kaio_ok | __uaio_ok) == 0)
		return;
	(void) fprintf(stderr, "\n");
	DISPLAY(_aio_freelist_cnt);
	DISPLAY(_aio_allocated_cnt);
	DISPLAY(_lio_alloc);
	DISPLAY(_lio_free);
	DISPLAY(__rw_workerscnt);
	DISPLAY(__no_workerscnt);
	DISPLAY(_aio_worker_cnt);
	DISPLAY(_aio_donecnt);
	DISPLAY(_aio_doneq_cnt);
	DISPLAY(_aio_waitncnt);
	DISPLAY(_aio_outstand_cnt);
	DISPLAY(_kaio_outstand_cnt);
	DISPLAY(_aio_req_done_cnt);
	DISPLAY(_aio_kernel_suspend);
	DISPLAY(_aio_suscv_cnt);
	DISPLAY(_aiowait_flag);
	DISPLAY(_aio_flags);
}

void
init_aio(void)
{
	char *str;

	(void) pthread_key_create(&_aio_key, _aio_worker_free);
	if ((str = getenv("_AIO_MIN_WORKERS")) != NULL) {
		if ((_min_workers = atoi(str)) <= 0)
			_min_workers = 4;
	}
	if ((str = getenv("_AIO_MAX_WORKERS")) != NULL) {
		if ((_max_workers = atoi(str)) <= 0)
			_max_workers = 256;
		if (_max_workers < _min_workers + 1)
			_max_workers = _min_workers + 1;
	}
	if ((str = getenv("_AIO_EXIT_INFO")) != NULL && atoi(str) != 0)
		(void) atexit(_aio_exit_info);
}
