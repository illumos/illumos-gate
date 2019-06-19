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

#include "lint.h"
#include "mtlib.h"
#define	_KMEMUSER
#include <sys/param.h>		/* _MQ_OPEN_MAX, _MQ_PRIO_MAX, _SEM_VALUE_MAX */
#undef	_KMEMUSER
#include <mqueue.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "sigev_thread.h"
#include "pos4obj.h"

/*
 * Default values per message queue
 */
#define	MQ_MAXMSG	128
#define	MQ_MAXSIZE	1024

#define	MQ_MAGIC	0x4d534751		/* "MSGQ" */

/*
 * Message header which is part of messages in link list
 */
typedef struct {
	uint64_t 	msg_next;	/* offset of next message in the link */
	uint64_t	msg_len;	/* length of the message */
} msghdr_t;

/*
 * message queue description
 */
struct mq_dn {
	size_t		mqdn_flags;	/* open description flags */
};

/*
 * message queue descriptor structure
 */
typedef struct mq_des {
	struct mq_des	*mqd_next;	/* list of all open mq descriptors, */
	struct mq_des	*mqd_prev;	/* needed for fork-safety */
	int		mqd_magic;	/* magic # to identify mq_des */
	int		mqd_flags;	/* operation flag per open */
	struct mq_header *mqd_mq;	/* address pointer of message Q */
	struct mq_dn	*mqd_mqdn;	/* open	description */
	thread_communication_data_t *mqd_tcd;	/* SIGEV_THREAD notification */
	int		mqd_ownerdead;	/* mq_exclusive is inconsistent */
} mqdes_t;

/*
 * message queue common header, part of the mmap()ed file.
 * Since message queues may be shared between 32- and 64-bit processes,
 * care must be taken to make sure that the elements of this structure
 * are identical for both _LP64 and _ILP32 cases.
 */
typedef struct mq_header {
	/* first field must be mq_totsize, DO NOT insert before this	*/
	int64_t		mq_totsize;	/* total size of the Queue */
	int64_t		mq_maxsz;	/* max size of each message */
	uint32_t	mq_maxmsg;	/* max messages in the queue */
	uint32_t	mq_maxprio;	/* maximum mqueue priority */
	uint32_t	mq_curmaxprio;	/* current maximum MQ priority */
	uint32_t	mq_mask;	/* priority bitmask */
	uint64_t	mq_freep;	/* free message's head pointer */
	uint64_t	mq_headpp;	/* pointer to head pointers */
	uint64_t	mq_tailpp;	/* pointer to tail pointers */
	signotify_id_t	mq_sigid;	/* notification id (3 int's) */
	uint32_t	mq_ntype;	/* notification type (SIGEV_*) */
	uint64_t	mq_des;		/* pointer to msg Q descriptor */
	mutex_t		mq_exclusive;	/* acquire for exclusive access */
	sem_t		mq_rblocked;	/* number of processes rblocked */
	sem_t		mq_notfull;	/* mq_send()'s block on this */
	sem_t		mq_notempty;	/* mq_receive()'s block on this */
	sem_t		mq_spawner;	/* spawner thread blocks on this */
} mqhdr_t;

/*
 * The code assumes that _MQ_OPEN_MAX == -1 or "no fixed implementation limit".
 * If this assumption is somehow invalidated, mq_open() needs to be changed
 * back to the old version which kept a count and enforced a limit.
 * We make sure that this is pointed out to those changing <sys/param.h>
 * by checking _MQ_OPEN_MAX at compile time.
 */
#if _MQ_OPEN_MAX != -1
#error "mq_open() no longer enforces _MQ_OPEN_MAX and needs fixing."
#endif

#define	MQ_ALIGNSIZE	8	/* 64-bit alignment */

#ifdef DEBUG
#define	MQ_ASSERT(x)	assert(x);

#define	MQ_ASSERT_PTR(_m, _p) \
	assert((_p) != NULL && !((uintptr_t)(_p) & (MQ_ALIGNSIZE -1)) && \
	    !((uintptr_t)_m + (uintptr_t)(_p) >= (uintptr_t)_m + \
	    _m->mq_totsize));

#define	MQ_ASSERT_SEMVAL_LEQ(sem, val) { \
	int _val; \
	(void) sem_getvalue((sem), &_val); \
	assert((_val) <= val); }
#else
#define	MQ_ASSERT(x)
#define	MQ_ASSERT_PTR(_m, _p)
#define	MQ_ASSERT_SEMVAL_LEQ(sem, val)
#endif

#define	MQ_PTR(m, n)	((msghdr_t *)((uintptr_t)m + (uintptr_t)n))
#define	HEAD_PTR(m, n)	((uint64_t *)((uintptr_t)m + \
			(uintptr_t)m->mq_headpp + n * sizeof (uint64_t)))
#define	TAIL_PTR(m, n)	((uint64_t *)((uintptr_t)m + \
			(uintptr_t)m->mq_tailpp + n * sizeof (uint64_t)))

#define	MQ_RESERVED	((mqdes_t *)-1)

#define	ABS_TIME	0
#define	REL_TIME	1

static mutex_t mq_list_lock = DEFAULTMUTEX;
static mqdes_t *mq_list = NULL;

extern int __signotify(int cmd, siginfo_t *sigonfo, signotify_id_t *sn_id);

static int
mq_is_valid(mqdes_t *mqdp)
{
	/*
	 * Any use of a message queue after it was closed is
	 * undefined.  But the standard strongly favours EBADF
	 * returns.  Before we dereference which could be fatal,
	 * we first do some pointer sanity checks.
	 */
	if (mqdp != NULL && mqdp != MQ_RESERVED &&
	    ((uintptr_t)mqdp & 0x7) == 0) {
		return (mqdp->mqd_magic == MQ_MAGIC);
	}

	return (0);
}

static void
mq_init(mqhdr_t *mqhp, size_t msgsize, ssize_t maxmsg)
{
	int		i;
	uint64_t	temp;
	uint64_t	currentp;
	uint64_t	nextp;

	/*
	 * We only need to initialize the non-zero fields.  The use of
	 * ftruncate() on the message queue file assures that the
	 * pages will be zero-filled.
	 */
	(void) mutex_init(&mqhp->mq_exclusive,
	    USYNC_PROCESS | LOCK_ROBUST, NULL);
	(void) sem_init(&mqhp->mq_rblocked, 1, 0);
	(void) sem_init(&mqhp->mq_notempty, 1, 0);
	(void) sem_init(&mqhp->mq_spawner, 1, 0);
	(void) sem_init(&mqhp->mq_notfull, 1, (uint_t)maxmsg);

	mqhp->mq_maxsz = msgsize;
	mqhp->mq_maxmsg = maxmsg;

	/*
	 * As of this writing (1997), there are 32 message queue priorities.
	 * If this is to change, then the size of the mq_mask will
	 * also have to change.  If DEBUG is defined, assert that
	 * _MQ_PRIO_MAX hasn't changed.
	 */
	mqhp->mq_maxprio = _MQ_PRIO_MAX;
#if defined(DEBUG)
	/* LINTED always true */
	MQ_ASSERT(sizeof (mqhp->mq_mask) * 8 >= _MQ_PRIO_MAX);
#endif

	/*
	 * Since the message queue can be mapped into different
	 * virtual address ranges by different processes, we don't
	 * keep track of pointers, only offsets into the shared region.
	 */
	mqhp->mq_headpp = sizeof (mqhdr_t);
	mqhp->mq_tailpp = mqhp->mq_headpp +
	    mqhp->mq_maxprio * sizeof (uint64_t);
	mqhp->mq_freep = mqhp->mq_tailpp +
	    mqhp->mq_maxprio * sizeof (uint64_t);

	currentp = mqhp->mq_freep;
	MQ_PTR(mqhp, currentp)->msg_next = 0;

	temp = (mqhp->mq_maxsz + MQ_ALIGNSIZE - 1) & ~(MQ_ALIGNSIZE - 1);
	for (i = 1; i < mqhp->mq_maxmsg; i++) {
		nextp = currentp + sizeof (msghdr_t) + temp;
		MQ_PTR(mqhp, currentp)->msg_next = nextp;
		MQ_PTR(mqhp, nextp)->msg_next = 0;
		currentp = nextp;
	}
}

static size_t
mq_getmsg(mqhdr_t *mqhp, char *msgp, uint_t *msg_prio)
{
	uint64_t currentp;
	msghdr_t *curbuf;
	uint64_t *headpp;
	uint64_t *tailpp;

	MQ_ASSERT(MUTEX_HELD(&mqhp->mq_exclusive));

	/*
	 * Get the head and tail pointers for the queue of maximum
	 * priority.  We shouldn't be here unless there is a message for
	 * us, so it's fair to assert that both the head and tail
	 * pointers are non-NULL.
	 */
	headpp = HEAD_PTR(mqhp, mqhp->mq_curmaxprio);
	tailpp = TAIL_PTR(mqhp, mqhp->mq_curmaxprio);

	if (msg_prio != NULL)
		*msg_prio = mqhp->mq_curmaxprio;

	currentp = *headpp;
	MQ_ASSERT_PTR(mqhp, currentp);
	curbuf = MQ_PTR(mqhp, currentp);

	if ((*headpp = curbuf->msg_next) == 0) {
		/*
		 * We just nuked the last message in this priority's queue.
		 * Twiddle this priority's bit, and then find the next bit
		 * tipped.
		 */
		uint_t prio = mqhp->mq_curmaxprio;

		mqhp->mq_mask &= ~(1u << prio);

		for (; prio != 0; prio--)
			if (mqhp->mq_mask & (1u << prio))
				break;
		mqhp->mq_curmaxprio = prio;

		*tailpp = 0;
	}

	/*
	 * Copy the message, and put the buffer back on the free list.
	 */
	(void) memcpy(msgp, (char *)&curbuf[1], curbuf->msg_len);
	curbuf->msg_next = mqhp->mq_freep;
	mqhp->mq_freep = currentp;

	return (curbuf->msg_len);
}


static void
mq_putmsg(mqhdr_t *mqhp, const char *msgp, ssize_t len, uint_t prio)
{
	uint64_t currentp;
	msghdr_t *curbuf;
	uint64_t *headpp;
	uint64_t *tailpp;

	MQ_ASSERT(MUTEX_HELD(&mqhp->mq_exclusive));

	/*
	 * Grab a free message block, and link it in.  We shouldn't
	 * be here unless there is room in the queue for us;  it's
	 * fair to assert that the free pointer is non-NULL.
	 */
	currentp = mqhp->mq_freep;
	MQ_ASSERT_PTR(mqhp, currentp);
	curbuf = MQ_PTR(mqhp, currentp);

	/*
	 * Remove a message from the free list, and copy in the new contents.
	 */
	mqhp->mq_freep = curbuf->msg_next;
	curbuf->msg_next = 0;
	(void) memcpy((char *)&curbuf[1], msgp, len);
	curbuf->msg_len = len;

	headpp = HEAD_PTR(mqhp, prio);
	tailpp = TAIL_PTR(mqhp, prio);

	if (*tailpp == 0) {
		/*
		 * This is the first message on this queue.  Set the
		 * head and tail pointers, and tip the appropriate bit
		 * in the priority mask.
		 */
		*headpp = currentp;
		*tailpp = currentp;
		mqhp->mq_mask |= (1u << prio);
		if (prio > mqhp->mq_curmaxprio)
			mqhp->mq_curmaxprio = prio;
	} else {
		MQ_ASSERT_PTR(mqhp, *tailpp);
		MQ_PTR(mqhp, *tailpp)->msg_next = currentp;
		*tailpp = currentp;
	}
}

/*
 * Send a notification and also delete the registration.
 */
static void
do_notify(mqhdr_t *mqhp)
{
	(void) __signotify(SN_SEND, NULL, &mqhp->mq_sigid);
	if (mqhp->mq_ntype == SIGEV_THREAD ||
	    mqhp->mq_ntype == SIGEV_PORT)
		(void) sem_post(&mqhp->mq_spawner);
	mqhp->mq_ntype = 0;
	mqhp->mq_des = 0;
}

/*
 * Called when the mq_exclusive lock draws EOWNERDEAD or ENOTRECOVERABLE.
 * Wake up anyone waiting on mq_*send() or mq_*receive() and ensure that
 * they fail with errno == EBADMSG.  Trigger any registered notification.
 */
static void
owner_dead(mqdes_t *mqdp, int error)
{
	mqhdr_t *mqhp = mqdp->mqd_mq;

	mqdp->mqd_ownerdead = 1;
	(void) sem_post(&mqhp->mq_notfull);
	(void) sem_post(&mqhp->mq_notempty);
	if (error == EOWNERDEAD) {
		if (mqhp->mq_sigid.sn_pid != 0)
			do_notify(mqhp);
		(void) mutex_unlock(&mqhp->mq_exclusive);
	}
	errno = EBADMSG;
}

mqd_t
mq_open(const char *path, int oflag, /* mode_t mode, mq_attr *attr */ ...)
{
	va_list		ap;
	mode_t		mode = 0;
	struct mq_attr	*attr = NULL;
	int		fd;
	int		err;
	int		cr_flag = 0;
	int		locked = 0;
	uint64_t	total_size;
	size_t		msgsize;
	ssize_t		maxmsg;
	uint64_t	temp;
	void		*ptr;
	mqdes_t		*mqdp;
	mqhdr_t		*mqhp;
	struct mq_dn	*mqdnp;

	if (__pos4obj_check(path) == -1)
		return ((mqd_t)-1);

	/* acquire MSGQ lock to have atomic operation */
	if (__pos4obj_lock(path, MQ_LOCK_TYPE) < 0)
		goto out;
	locked = 1;

	va_start(ap, oflag);
	/* filter oflag to have READ/WRITE/CREATE modes only */
	oflag = oflag & (O_RDONLY|O_WRONLY|O_RDWR|O_CREAT|O_EXCL|O_NONBLOCK);
	if ((oflag & O_CREAT) != 0) {
		mode = va_arg(ap, mode_t);
		attr = va_arg(ap, struct mq_attr *);
	}
	va_end(ap);

	if ((fd = __pos4obj_open(path, MQ_PERM_TYPE, oflag,
	    mode, &cr_flag)) < 0)
		goto out;

	/* closing permission file */
	(void) __close_nc(fd);

	/* Try to open/create data file */
	if (cr_flag) {
		cr_flag = PFILE_CREATE;
		if (attr == NULL) {
			maxmsg = MQ_MAXMSG;
			msgsize = MQ_MAXSIZE;
		} else if (attr->mq_maxmsg <= 0 || attr->mq_msgsize <= 0) {
			errno = EINVAL;
			goto out;
		} else if (attr->mq_maxmsg > _SEM_VALUE_MAX) {
			errno = ENOSPC;
			goto out;
		} else {
			maxmsg = attr->mq_maxmsg;
			msgsize = attr->mq_msgsize;
		}

		/* adjust for message size at word boundary */
		temp = (msgsize + MQ_ALIGNSIZE - 1) & ~(MQ_ALIGNSIZE - 1);

		total_size = sizeof (mqhdr_t) +
		    maxmsg * (temp + sizeof (msghdr_t)) +
		    2 * _MQ_PRIO_MAX * sizeof (uint64_t);

		if (total_size > SSIZE_MAX) {
			errno = ENOSPC;
			goto out;
		}

		/*
		 * data file is opened with read/write to those
		 * who have read or write permission
		 */
		mode = mode | (mode & 0444) >> 1 | (mode & 0222) << 1;
		if ((fd = __pos4obj_open(path, MQ_DATA_TYPE,
		    (O_RDWR|O_CREAT|O_EXCL), mode, &err)) < 0)
			goto out;

		cr_flag |= DFILE_CREATE | DFILE_OPEN;

		/* force permissions to avoid umask effect */
		if (fchmod(fd, mode) < 0)
			goto out;

		if (ftruncate64(fd, (off64_t)total_size) < 0)
			goto out;
	} else {
		if ((fd = __pos4obj_open(path, MQ_DATA_TYPE,
		    O_RDWR, 0666, &err)) < 0)
			goto out;
		cr_flag = DFILE_OPEN;

		/* Message queue has not been initialized yet */
		if (read(fd, &total_size, sizeof (total_size)) !=
		    sizeof (total_size) || total_size == 0) {
			errno = ENOENT;
			goto out;
		}

		/* Message queue too big for this process to handle */
		if (total_size > SSIZE_MAX) {
			errno = EFBIG;
			goto out;
		}
	}

	if ((mqdp = (mqdes_t *)malloc(sizeof (mqdes_t))) == NULL) {
		errno = ENOMEM;
		goto out;
	}
	cr_flag |= ALLOC_MEM;

	if ((ptr = mmap64(NULL, total_size, PROT_READ|PROT_WRITE,
	    MAP_SHARED, fd, (off64_t)0)) == MAP_FAILED)
		goto out;
	mqhp = ptr;
	cr_flag |= DFILE_MMAP;

	/* closing data file */
	(void) __close_nc(fd);
	cr_flag &= ~DFILE_OPEN;

	/*
	 * create, unlink, size, mmap, and close description file
	 * all for a flag word in anonymous shared memory
	 */
	if ((fd = __pos4obj_open(path, MQ_DSCN_TYPE, O_RDWR | O_CREAT,
	    0666, &err)) < 0)
		goto out;
	cr_flag |= DFILE_OPEN;
	(void) __pos4obj_unlink(path, MQ_DSCN_TYPE);
	if (ftruncate64(fd, (off64_t)sizeof (struct mq_dn)) < 0)
		goto out;

	if ((ptr = mmap64(NULL, sizeof (struct mq_dn),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off64_t)0)) == MAP_FAILED)
		goto out;
	mqdnp = ptr;
	cr_flag |= MQDNP_MMAP;

	(void) __close_nc(fd);
	cr_flag &= ~DFILE_OPEN;

	/*
	 * we follow the same strategy as filesystem open() routine,
	 * where fcntl.h flags are changed to flags defined in file.h.
	 */
	mqdp->mqd_flags = (oflag - FOPEN) & (FREAD|FWRITE);
	mqdnp->mqdn_flags = (oflag - FOPEN) & (FNONBLOCK);

	/* new message queue requires initialization */
	if ((cr_flag & DFILE_CREATE) != 0) {
		/* message queue header has to be initialized */
		mq_init(mqhp, msgsize, maxmsg);
		mqhp->mq_totsize = total_size;
	}
	mqdp->mqd_mq = mqhp;
	mqdp->mqd_mqdn = mqdnp;
	mqdp->mqd_magic = MQ_MAGIC;
	mqdp->mqd_tcd = NULL;
	mqdp->mqd_ownerdead = 0;
	if (__pos4obj_unlock(path, MQ_LOCK_TYPE) == 0) {
		lmutex_lock(&mq_list_lock);
		mqdp->mqd_next = mq_list;
		mqdp->mqd_prev = NULL;
		if (mq_list)
			mq_list->mqd_prev = mqdp;
		mq_list = mqdp;
		lmutex_unlock(&mq_list_lock);
		return ((mqd_t)mqdp);
	}

	locked = 0;	/* fall into the error case */
out:
	err = errno;
	if ((cr_flag & DFILE_OPEN) != 0)
		(void) __close_nc(fd);
	if ((cr_flag & DFILE_CREATE) != 0)
		(void) __pos4obj_unlink(path, MQ_DATA_TYPE);
	if ((cr_flag & PFILE_CREATE) != 0)
		(void) __pos4obj_unlink(path, MQ_PERM_TYPE);
	if ((cr_flag & ALLOC_MEM) != 0)
		free((void *)mqdp);
	if ((cr_flag & DFILE_MMAP) != 0)
		(void) munmap((caddr_t)mqhp, (size_t)total_size);
	if ((cr_flag & MQDNP_MMAP) != 0)
		(void) munmap((caddr_t)mqdnp, sizeof (struct mq_dn));
	if (locked)
		(void) __pos4obj_unlock(path, MQ_LOCK_TYPE);
	errno = err;
	return ((mqd_t)-1);
}

static void
mq_close_cleanup(mqdes_t *mqdp)
{
	mqhdr_t *mqhp = mqdp->mqd_mq;
	struct mq_dn *mqdnp = mqdp->mqd_mqdn;

	/* invalidate the descriptor before freeing it */
	mqdp->mqd_magic = 0;
	if (!mqdp->mqd_ownerdead)
		(void) mutex_unlock(&mqhp->mq_exclusive);

	lmutex_lock(&mq_list_lock);
	if (mqdp->mqd_next)
		mqdp->mqd_next->mqd_prev = mqdp->mqd_prev;
	if (mqdp->mqd_prev)
		mqdp->mqd_prev->mqd_next = mqdp->mqd_next;
	if (mq_list == mqdp)
		mq_list = mqdp->mqd_next;
	lmutex_unlock(&mq_list_lock);

	free(mqdp);
	(void) munmap((caddr_t)mqdnp, sizeof (struct mq_dn));
	(void) munmap((caddr_t)mqhp, (size_t)mqhp->mq_totsize);
}

int
mq_close(mqd_t mqdes)
{
	mqdes_t *mqdp = (mqdes_t *)mqdes;
	mqhdr_t *mqhp;
	thread_communication_data_t *tcdp;
	int error;

	if (!mq_is_valid(mqdp)) {
		errno = EBADF;
		return (-1);
	}

	mqhp = mqdp->mqd_mq;
	if ((error = mutex_lock(&mqhp->mq_exclusive)) != 0) {
		mqdp->mqd_ownerdead = 1;
		if (error == EOWNERDEAD)
			(void) mutex_unlock(&mqhp->mq_exclusive);
		/* carry on regardless, without holding mq_exclusive */
	}

	if (mqhp->mq_des == (uintptr_t)mqdp &&
	    mqhp->mq_sigid.sn_pid == getpid()) {
		/* notification is set for this descriptor, remove it */
		(void) __signotify(SN_CANCEL, NULL, &mqhp->mq_sigid);
		mqhp->mq_ntype = 0;
		mqhp->mq_des = 0;
	}

	pthread_cleanup_push(mq_close_cleanup, mqdp);
	if ((tcdp = mqdp->mqd_tcd) != NULL) {
		mqdp->mqd_tcd = NULL;
		del_sigev_mq(tcdp);	/* possible cancellation point */
	}
	pthread_cleanup_pop(1);		/* finish in the cleanup handler */

	return (0);
}

int
mq_unlink(const char *path)
{
	int err;

	if (__pos4obj_check(path) < 0)
		return (-1);

	if (__pos4obj_lock(path, MQ_LOCK_TYPE) < 0) {
		return (-1);
	}

	err = __pos4obj_unlink(path, MQ_PERM_TYPE);

	if (err == 0 || (err == -1 && errno == EEXIST)) {
		errno = 0;
		err = __pos4obj_unlink(path, MQ_DATA_TYPE);
	}

	if (__pos4obj_unlock(path, MQ_LOCK_TYPE) < 0)
		return (-1);

	return (err);

}

static int
__mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	uint_t msg_prio, const timespec_t *timeout, int abs_rel)
{
	mqdes_t *mqdp = (mqdes_t *)mqdes;
	mqhdr_t *mqhp;
	int err;
	int notify = 0;

	/*
	 * sem_*wait() does cancellation, if called.
	 * pthread_testcancel() ensures that cancellation takes place if
	 * there is a cancellation pending when mq_*send() is called.
	 */
	pthread_testcancel();

	if (!mq_is_valid(mqdp) || (mqdp->mqd_flags & FWRITE) == 0) {
		errno = EBADF;
		return (-1);
	}

	mqhp = mqdp->mqd_mq;

	if (msg_prio >= mqhp->mq_maxprio) {
		errno = EINVAL;
		return (-1);
	}
	if (msg_len > mqhp->mq_maxsz) {
		errno = EMSGSIZE;
		return (-1);
	}

	if (mqdp->mqd_mqdn->mqdn_flags & O_NONBLOCK)
		err = sem_trywait(&mqhp->mq_notfull);
	else {
		/*
		 * We might get cancelled here...
		 */
		if (timeout == NULL)
			err = sem_wait(&mqhp->mq_notfull);
		else if (abs_rel == ABS_TIME)
			err = sem_timedwait(&mqhp->mq_notfull, timeout);
		else
			err = sem_reltimedwait_np(&mqhp->mq_notfull, timeout);
	}
	if (err == -1) {
		/*
		 * errno has been set to EAGAIN / EINTR / ETIMEDOUT
		 * by sem_*wait(), so we can just return.
		 */
		return (-1);
	}

	/*
	 * By the time we're here, we know that we've got the capacity
	 * to add to the queue...now acquire the exclusive lock.
	 */
	if ((err = mutex_lock(&mqhp->mq_exclusive)) != 0) {
		owner_dead(mqdp, err);
		return (-1);
	}

	/*
	 * Now determine if we want to kick the notification.  POSIX
	 * requires that if a process has registered for notification,
	 * we must kick it when the queue makes an empty to non-empty
	 * transition, and there are no blocked receivers.  Note that
	 * this mechanism does _not_ guarantee that the kicked process
	 * will be able to receive a message without blocking;
	 * another receiver could intervene in the meantime.  Thus,
	 * the notification mechanism is inherently racy; all we can
	 * do is hope to minimize the window as much as possible.
	 * In general, we want to avoid kicking the notification when
	 * there are clearly receivers blocked.  We'll determine if
	 * we want to kick the notification before the mq_putmsg(),
	 * but the actual signotify() won't be done until the message
	 * is on the queue.
	 */
	if (mqhp->mq_sigid.sn_pid != 0) {
		int nmessages, nblocked;

		(void) sem_getvalue(&mqhp->mq_notempty, &nmessages);
		(void) sem_getvalue(&mqhp->mq_rblocked, &nblocked);

		if (nmessages == 0 && nblocked == 0)
			notify = 1;
	}

	mq_putmsg(mqhp, msg_ptr, (ssize_t)msg_len, msg_prio);
	(void) sem_post(&mqhp->mq_notempty);

	if (notify) {
		/* notify and also delete the registration */
		do_notify(mqhp);
	}

	MQ_ASSERT_SEMVAL_LEQ(&mqhp->mq_notempty, ((int)mqhp->mq_maxmsg));
	(void) mutex_unlock(&mqhp->mq_exclusive);

	return (0);
}

int
mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, uint_t msg_prio)
{
	return (__mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio,
	    NULL, ABS_TIME));
}

int
mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	uint_t msg_prio, const timespec_t *abs_timeout)
{
	return (__mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio,
	    abs_timeout, ABS_TIME));
}

int
mq_reltimedsend_np(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	uint_t msg_prio, const timespec_t *rel_timeout)
{
	return (__mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio,
	    rel_timeout, REL_TIME));
}

static void
decrement_rblocked(mqhdr_t *mqhp)
{
	int cancel_state;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	while (sem_wait(&mqhp->mq_rblocked) == -1)
		continue;
	(void) pthread_setcancelstate(cancel_state, NULL);
}

static ssize_t
__mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	uint_t *msg_prio, const timespec_t *timeout, int abs_rel)
{
	mqdes_t *mqdp = (mqdes_t *)mqdes;
	mqhdr_t *mqhp;
	ssize_t	msg_size;
	int err;

	/*
	 * sem_*wait() does cancellation, if called.
	 * pthread_testcancel() ensures that cancellation takes place if
	 * there is a cancellation pending when mq_*receive() is called.
	 */
	pthread_testcancel();

	if (!mq_is_valid(mqdp) || (mqdp->mqd_flags & FREAD) == 0) {
		errno = EBADF;
		return (ssize_t)(-1);
	}

	mqhp = mqdp->mqd_mq;

	if (msg_len < mqhp->mq_maxsz) {
		errno = EMSGSIZE;
		return (ssize_t)(-1);
	}

	/*
	 * The semaphoring scheme for mq_[timed]receive is a little hairy
	 * thanks to POSIX.1b's arcane notification mechanism.  First,
	 * we try to take the common case and do a sem_trywait().
	 * If that doesn't work, and O_NONBLOCK hasn't been set,
	 * then note that we're going to sleep by incrementing the rblocked
	 * semaphore.  We decrement that semaphore after waking up.
	 */
	if (sem_trywait(&mqhp->mq_notempty) == -1) {
		if ((mqdp->mqd_mqdn->mqdn_flags & O_NONBLOCK) != 0) {
			/*
			 * errno has been set to EAGAIN or EINTR by
			 * sem_trywait(), so we can just return.
			 */
			return (-1);
		}
		/*
		 * If we're here, then we're probably going to block...
		 * increment the rblocked semaphore.  If we get
		 * cancelled, decrement_rblocked() will decrement it.
		 */
		(void) sem_post(&mqhp->mq_rblocked);

		pthread_cleanup_push(decrement_rblocked, mqhp);
		if (timeout == NULL)
			err = sem_wait(&mqhp->mq_notempty);
		else if (abs_rel == ABS_TIME)
			err = sem_timedwait(&mqhp->mq_notempty, timeout);
		else
			err = sem_reltimedwait_np(&mqhp->mq_notempty, timeout);
		pthread_cleanup_pop(1);

		if (err == -1) {
			/*
			 * We took a signal or timeout while waiting
			 * on mq_notempty...
			 */
			return (-1);
		}
	}

	if ((err = mutex_lock(&mqhp->mq_exclusive)) != 0) {
		owner_dead(mqdp, err);
		return (-1);
	}
	msg_size = mq_getmsg(mqhp, msg_ptr, msg_prio);
	(void) sem_post(&mqhp->mq_notfull);
	MQ_ASSERT_SEMVAL_LEQ(&mqhp->mq_notfull, ((int)mqhp->mq_maxmsg));
	(void) mutex_unlock(&mqhp->mq_exclusive);

	return (msg_size);
}

ssize_t
mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, uint_t *msg_prio)
{
	return (__mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio,
	    NULL, ABS_TIME));
}

ssize_t
mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	uint_t *msg_prio, const timespec_t *abs_timeout)
{
	return (__mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio,
	    abs_timeout, ABS_TIME));
}

ssize_t
mq_reltimedreceive_np(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	uint_t *msg_prio, const timespec_t *rel_timeout)
{
	return (__mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio,
	    rel_timeout, REL_TIME));
}

/*
 * Only used below, in mq_notify().
 * We already have a spawner thread.
 * Verify that the attributes match; cancel it if necessary.
 */
static int
cancel_if_necessary(thread_communication_data_t *tcdp,
	const struct sigevent *sigevp)
{
	int do_cancel = !pthread_attr_equal(tcdp->tcd_attrp,
	    sigevp->sigev_notify_attributes);

	if (do_cancel) {
		/*
		 * Attributes don't match, cancel the spawner thread.
		 */
		(void) pthread_cancel(tcdp->tcd_server_id);
	} else {
		/*
		 * Reuse the existing spawner thread with possibly
		 * changed notification function and value.
		 */
		tcdp->tcd_notif.sigev_notify = SIGEV_THREAD;
		tcdp->tcd_notif.sigev_signo = 0;
		tcdp->tcd_notif.sigev_value = sigevp->sigev_value;
		tcdp->tcd_notif.sigev_notify_function =
		    sigevp->sigev_notify_function;
	}

	return (do_cancel);
}

int
mq_notify(mqd_t mqdes, const struct sigevent *sigevp)
{
	mqdes_t *mqdp = (mqdes_t *)mqdes;
	mqhdr_t *mqhp;
	thread_communication_data_t *tcdp;
	siginfo_t mq_siginfo;
	struct sigevent sigevent;
	struct stat64 statb;
	port_notify_t *pn;
	void *userval;
	int rval = -1;
	int ntype;
	int port;
	int error;

	if (!mq_is_valid(mqdp)) {
		errno = EBADF;
		return (-1);
	}

	mqhp = mqdp->mqd_mq;

	if ((error = mutex_lock(&mqhp->mq_exclusive)) != 0) {
		mqdp->mqd_ownerdead = 1;
		sigevp = NULL;
		if (error == EOWNERDEAD)
			(void) mutex_unlock(&mqhp->mq_exclusive);
		/* carry on regardless, without holding mq_exclusive */
	}

	if (sigevp == NULL) {		/* remove notification */
		if (mqhp->mq_des == (uintptr_t)mqdp &&
		    mqhp->mq_sigid.sn_pid == getpid()) {
			/* notification is set for this descriptor, remove it */
			(void) __signotify(SN_CANCEL, NULL, &mqhp->mq_sigid);
			if ((tcdp = mqdp->mqd_tcd) != NULL) {
				sig_mutex_lock(&tcdp->tcd_lock);
				if (tcdp->tcd_msg_enabled) {
					/* cancel the spawner thread */
					tcdp = mqdp->mqd_tcd;
					mqdp->mqd_tcd = NULL;
					(void) pthread_cancel(
					    tcdp->tcd_server_id);
				}
				sig_mutex_unlock(&tcdp->tcd_lock);
			}
			mqhp->mq_ntype = 0;
			mqhp->mq_des = 0;
		} else {
			/* notification is not set for this descriptor */
			errno = EBUSY;
			goto bad;
		}
	} else {		/* register notification with this process */
		switch (ntype = sigevp->sigev_notify) {
		case SIGEV_THREAD:
			userval = sigevp->sigev_value.sival_ptr;
			port = -1;
			break;
		case SIGEV_PORT:
			pn = sigevp->sigev_value.sival_ptr;
			userval = pn->portnfy_user;
			port = pn->portnfy_port;
			if (fstat64(port, &statb) != 0 ||
			    !S_ISPORT(statb.st_mode)) {
				errno = EBADF;
				goto bad;
			}
			(void) memset(&sigevent, 0, sizeof (sigevent));
			sigevent.sigev_notify = SIGEV_PORT;
			sigevp = &sigevent;
			break;
		}
		switch (ntype) {
		case SIGEV_NONE:
			mq_siginfo.si_signo = 0;
			mq_siginfo.si_code = SI_MESGQ;
			break;
		case SIGEV_SIGNAL:
			mq_siginfo.si_signo = sigevp->sigev_signo;
			mq_siginfo.si_value = sigevp->sigev_value;
			mq_siginfo.si_code = SI_MESGQ;
			break;
		case SIGEV_THREAD:
			if ((tcdp = mqdp->mqd_tcd) != NULL &&
			    cancel_if_necessary(tcdp, sigevp))
				mqdp->mqd_tcd = NULL;
			/* FALLTHROUGH */
		case SIGEV_PORT:
			if ((tcdp = mqdp->mqd_tcd) == NULL) {
				/* we must create a spawner thread */
				tcdp = setup_sigev_handler(sigevp, MQ);
				if (tcdp == NULL) {
					errno = EBADF;
					goto bad;
				}
				tcdp->tcd_msg_enabled = 0;
				tcdp->tcd_msg_closing = 0;
				tcdp->tcd_msg_avail = &mqhp->mq_spawner;
				if (launch_spawner(tcdp) != 0) {
					free_sigev_handler(tcdp);
					goto bad;
				}
				mqdp->mqd_tcd = tcdp;
			}
			mq_siginfo.si_signo = 0;
			mq_siginfo.si_code = SI_MESGQ;
			break;
		default:
			errno = EINVAL;
			goto bad;
		}

		/* register notification */
		if (__signotify(SN_PROC, &mq_siginfo, &mqhp->mq_sigid) < 0)
			goto bad;
		mqhp->mq_ntype = ntype;
		mqhp->mq_des = (uintptr_t)mqdp;
		switch (ntype) {
		case SIGEV_THREAD:
		case SIGEV_PORT:
			tcdp->tcd_port = port;
			tcdp->tcd_msg_object = mqdp;
			tcdp->tcd_msg_userval = userval;
			sig_mutex_lock(&tcdp->tcd_lock);
			tcdp->tcd_msg_enabled = ntype;
			sig_mutex_unlock(&tcdp->tcd_lock);
			(void) cond_broadcast(&tcdp->tcd_cv);
			break;
		}
	}

	rval = 0;	/* success */
bad:
	if (error == 0) {
		(void) mutex_unlock(&mqhp->mq_exclusive);
	} else {
		errno = EBADMSG;
		rval = -1;
	}
	return (rval);
}

int
mq_setattr(mqd_t mqdes, const struct mq_attr *mqstat, struct mq_attr *omqstat)
{
	mqdes_t *mqdp = (mqdes_t *)mqdes;
	mqhdr_t *mqhp;
	uint_t	flag = 0;

	if (!mq_is_valid(mqdp)) {
		errno = EBADF;
		return (-1);
	}

	/* store current attributes */
	if (omqstat != NULL) {
		int	count;

		mqhp = mqdp->mqd_mq;
		omqstat->mq_flags = mqdp->mqd_mqdn->mqdn_flags;
		omqstat->mq_maxmsg = (long)mqhp->mq_maxmsg;
		omqstat->mq_msgsize = (long)mqhp->mq_maxsz;
		(void) sem_getvalue(&mqhp->mq_notempty, &count);
		omqstat->mq_curmsgs = count;
	}

	/* set description attributes */
	if ((mqstat->mq_flags & O_NONBLOCK) != 0)
		flag = FNONBLOCK;
	mqdp->mqd_mqdn->mqdn_flags = flag;

	return (0);
}

int
mq_getattr(mqd_t mqdes, struct mq_attr *mqstat)
{
	mqdes_t *mqdp = (mqdes_t *)mqdes;
	mqhdr_t *mqhp;
	int count;

	if (!mq_is_valid(mqdp)) {
		errno = EBADF;
		return (-1);
	}

	mqhp = mqdp->mqd_mq;

	mqstat->mq_flags = mqdp->mqd_mqdn->mqdn_flags;
	mqstat->mq_maxmsg = (long)mqhp->mq_maxmsg;
	mqstat->mq_msgsize = (long)mqhp->mq_maxsz;
	(void) sem_getvalue(&mqhp->mq_notempty, &count);
	mqstat->mq_curmsgs = count;
	return (0);
}

/*
 * Cleanup after fork1() in the child process.
 */
void
postfork1_child_sigev_mq(void)
{
	thread_communication_data_t *tcdp;
	mqdes_t *mqdp;

	for (mqdp = mq_list; mqdp; mqdp = mqdp->mqd_next) {
		if ((tcdp = mqdp->mqd_tcd) != NULL) {
			mqdp->mqd_tcd = NULL;
			tcd_teardown(tcdp);
		}
	}
}
