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
 * Copyright 2015 Gary Mills
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include "db_dictionary_c.h"
#include "nisdb_rw.h"
#include "nisdb_ldap.h"

/*
 * Nesting-safe RW locking functions. Return 0 when successful, an
 * error number from the E-series when not.
 */

int
__nisdb_rwinit(__nisdb_rwlock_t *rw) {

	int	ret;

	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if ((ret = mutex_init(&rw->mutex, USYNC_THREAD, 0)) != 0)
		return (ret);
	if ((ret = cond_init(&rw->cv, USYNC_THREAD, 0)) != 0)
		return (ret);
	rw->destroyed = 0;

	/*
	 * If we allow read-to-write lock migration, there's a potential
	 * race condition if two or more threads want to upgrade at the
	 * same time. The simple and safe (but crude and possibly costly)
	 * method to fix this is to always use exclusive locks, and so
	 * that has to be the default.
	 *
	 * There are two conditions under which it is safe to set
	 * 'force_write' to zero for a certain lock structure:
	 *
	 * (1)	The lock will never be subject to migration, or
	 *
	 * (2)	It's OK if the data protected by the lock has changed
	 *	(a)	Every time the lock (read or write) has been
	 *		acquired (even if the lock already was held by
	 *		the thread), and
	 *	(b)	After every call to a function that might have
	 *		acquired the lock.
	 */
	rw->force_write = NISDB_FORCE_WRITE;

	rw->writer_count = rw->reader_count = rw->reader_blocked = 0;
	rw->writer.id = rw->reader.id = INV_PTHREAD_ID;
	rw->writer.count = rw->reader.count = 0;
	rw->writer.next = rw->reader.next = 0;

	return (0);
}


static __nisdb_rl_t *
find_reader(pthread_t id, __nisdb_rwlock_t *rw) {

	__nisdb_rl_t	*rr;

	for (rr = &rw->reader; rr != 0; rr = rr->next) {
		if (rr->id == INV_PTHREAD_ID) {
			rr = 0;
			break;
		}
		if (rr->id == id)
			break;
	}

	return (rr);
}


int
__nisdb_rw_readlock_ok(__nisdb_rwlock_t *rw) {
	int		ret;

	if (rw == 0)
		return (EFAULT);

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	/*
	 * Only allow changing 'force_write' when it's really safe; i.e.,
	 * the lock hasn't been destroyed, and there are no readers.
	 */
	if (rw->destroyed == 0 && rw->reader_count == 0) {
		rw->force_write = 0;
		ret = 0;
	} else {
		ret = EBUSY;
	}

	(void) mutex_unlock(&rw->mutex);

	return (ret);
}


int
__nisdb_rw_force_writelock(__nisdb_rwlock_t *rw) {
	int		ret;

	if (rw == 0 || rw->destroyed != 0)
		return (ESHUTDOWN);

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	/*
	 * Only allow changing 'force_write' when it's really safe; i.e.,
	 * the lock hasn't been destroyed, and there are no readers.
	 */
	if (rw->destroyed == 0 && rw->reader_count == 0) {
		rw->force_write = 1;
		ret = 0;
	} else {
		ret = EBUSY;
	}

	(void) mutex_unlock(&rw->mutex);

	return (ret);
}


int
__nisdb_wlock_trylock(__nisdb_rwlock_t *rw, int trylock) {

	int		ret;
	pthread_t	myself = pthread_self();
	int		all_readers_blocked = 0;
	__nisdb_rl_t	*rr = 0;

	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		/* This shouldn't happen */
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	/* Simplest (and probably most common) case: no readers or writers */
	if (rw->reader_count == 0 && rw->writer_count == 0) {
		rw->writer_count = 1;
		rw->writer.id = myself;
		rw->writer.count = 1;
		return (mutex_unlock(&rw->mutex));
	}

	/*
	 * Need to know if we're holding a read lock already, and if
	 * all other readers are blocked waiting for the mutex.
	 */
	if (rw->reader_count > 0) {
		if ((rr = find_reader(myself, rw)) != 0) {
			if (rr->count) {
				/*
				 * We're already holding a read lock, so
				 * if the number of readers equals the number
				 * of blocked readers plus one, all other
				 * readers are blocked.
				 */
				if (rw->reader_count ==
						(rw->reader_blocked + 1))
					all_readers_blocked = 1;
			} else {
				/*
				 * We're not holding a read lock, so the
				 * number of readers should equal the number
				 * of blocked readers if all readers are
				 * blocked.
				 */
				if (rw->reader_count == rw->reader_blocked)
					all_readers_blocked = 1;
			}
		}
	}

	/* Wait for reader(s) or writer to finish */
	while (1) {
		/*
		 * We can stop looping if one of the following holds:
		 *	- No readers, no writers
		 *	- No writers (or writer is myself), and one of:
		 *		- No readers
		 *		- One reader, and it's us
		 *		- N readers, but all blocked on the mutex
		 */
		if (
		    (rw->writer_count == 0 && rw->reader_count == 0) ||
		    (((rw->writer_count == 0 || rw->writer.id == myself) &&
		    (rw->reader_count == 0)) ||
		    (rw->reader_count == 1 &&
		    rw->reader.id == myself))) {
			break;
		}
		/*
		 * Provided that all readers are blocked on the mutex
		 * we break a potential dead-lock by acquiring the
		 * write lock.
		 */
		if (all_readers_blocked) {
			if (rw->writer_count == 0 || rw->writer.id == myself) {
				break;
			}
		}

		/*
		 * If 'trylock' is set, tell the caller that we'd have to
		 * block to obtain the lock.
		 */
		if (trylock) {
			(void) mutex_unlock(&rw->mutex);
			return (EBUSY);
		}

		/* If we're also a reader, indicate that we're blocking */
		if (rr != 0) {
			rr->wait = 1;
			rw->reader_blocked++;
		}
		if ((ret = cond_wait(&rw->cv, &rw->mutex)) != 0) {
			if (rr != 0) {
				rr->wait = 0;
				if (rw->reader_blocked > 0)
					rw->reader_blocked--;
#ifdef	NISDB_MT_DEBUG
				else
					abort();
#endif	/* NISDB_MT_DEBUG */
			}
			(void) mutex_unlock(&rw->mutex);
			return (ret);
		}
		if (rr != 0) {
			rr->wait = 0;
			if (rw->reader_blocked > 0)
				rw->reader_blocked--;
#ifdef	NISDB_MT_DEBUG
			else
				abort();
#endif	/* NISDB_MT_DEBUG */
		}
	}

	/* OK to grab the write lock */
	rw->writer.id = myself;
	/* Increment lock depth */
	rw->writer.count++;
	/* Set number of writers (doesn't increase with lock depth) */
	if (rw->writer_count == 0)
		rw->writer_count = 1;

	return (mutex_unlock(&rw->mutex));
}

int
__nisdb_wlock(__nisdb_rwlock_t *rw) {
	return (__nisdb_wlock_trylock(rw, 0));
}


static __nisdb_rl_t *
increment_reader(pthread_t id, __nisdb_rwlock_t *rw) {

	__nisdb_rl_t	*rr;

	for (rr = &rw->reader; rr != 0; rr = rr->next) {
		if (rr->id == id || rr->id == INV_PTHREAD_ID)
			break;
	}
	if (rw->reader_count == 0 && rr == &rw->reader) {
		/* No previous reader */
		rr->id = id;
		rw->reader_count = 1;
	} else if (rr == 0) {
		if ((rr = malloc(sizeof (__nisdb_rl_t))) == 0)
			return (0);
		rr->id = id;
		rr->count = 0;
		/*
		 * For insertion simplicity, make it the second item
		 * on the list.
		 */
		rr->next = rw->reader.next;
		rw->reader.next = rr;
		rw->reader_count++;
	}
	rr->count++;

	return (rr);
}


int
__nisdb_rlock(__nisdb_rwlock_t *rw) {

	int		ret;
	pthread_t	myself = pthread_self();
	__nisdb_rl_t	*rr;

	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		/* This shouldn't happen */
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if (rw->force_write)
		return (__nisdb_wlock(rw));

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	rr = find_reader(myself, rw);

	/* Wait for writer to complete; writer == myself also OK */
	while (rw->writer_count > 0 && rw->writer.id != myself) {
		if (rr != 0) {
			rr->wait = 1;
			rw->reader_blocked++;
		}
		if ((ret = cond_wait(&rw->cv, &rw->mutex)) != 0) {
			if (rr != 0) {
				rr->wait = 0;
				if (rw->reader_blocked > 0)
					rw->reader_blocked--;
#ifdef	NISDB_MT_DEBUG
				else
					abort();
#endif	/* NISDB_MT_DEBUG */
			}
			(void) mutex_unlock(&rw->mutex);
			return (ret);
		}
		if (rr != 0) {
			rr->wait = 0;
			if (rw->reader_blocked > 0)
				rw->reader_blocked--;
#ifdef	NISDB_MT_DEBUG
			else
				abort();
#endif	/* NISDB_MT_DEBUG */
		}
	}

	rr = increment_reader(myself, rw);
	ret = mutex_unlock(&rw->mutex);
	return ((rr == 0) ? ENOMEM : ret);
}


int
__nisdb_wulock(__nisdb_rwlock_t *rw) {

	int		ret;
	pthread_t	myself = pthread_self();

	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		/* This shouldn't happen */
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	/* Sanity check */
	if (rw->writer_count == 0 ||
		rw->writer.id != myself || rw->writer.count == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		(void) mutex_unlock(&rw->mutex);
		return (ENOLCK);
	}

	rw->writer.count--;
	if (rw->writer.count == 0) {
		rw->writer.id = INV_PTHREAD_ID;
		rw->writer_count = 0;
		if ((ret = cond_broadcast(&rw->cv)) != 0) {
			(void) mutex_unlock(&rw->mutex);
			return (ret);
		}
	}

	return (mutex_unlock(&rw->mutex));
}


int
__nisdb_rulock(__nisdb_rwlock_t *rw) {

	int		ret;
	pthread_t	myself = pthread_self();
	__nisdb_rl_t	*rr, *prev;

	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if (rw->force_write)
		return (__nisdb_wulock(rw));

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	/* Sanity check */
	if (rw->reader_count == 0 ||
		(rw->writer_count > 0 && rw->writer.id != myself)) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		(void) mutex_unlock(&rw->mutex);
		return (ENOLCK);
	}

	/* Find the reader record */
	for (rr = &rw->reader, prev = 0; rr != 0; prev = rr, rr = rr->next) {
		if (rr->id == myself)
			break;
	}

	if (rr == 0 || rr->count == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		(void) mutex_unlock(&rw->mutex);
		return (ENOLCK);
	}

	rr->count--;
	if (rr->count == 0) {
		if (rr != &rw->reader) {
			/* Remove item from list and free it */
			prev->next = rr->next;
			free(rr);
		} else {
			/*
			 * First record: copy second to first, and free second
			 * record.
			 */
			if (rr->next != 0) {
				rr = rr->next;
				rw->reader.id = rr->id;
				rw->reader.count = rr->count;
				rw->reader.next = rr->next;
				free(rr);
			} else {
				/* Decomission the first record */
				rr->id = INV_PTHREAD_ID;
			}
		}
		rw->reader_count--;
	}

	/* If there are no readers, wake up any waiting writer */
	if (rw->reader_count == 0) {
		if ((ret = cond_broadcast(&rw->cv)) != 0) {
			(void) mutex_unlock(&rw->mutex);
			return (ret);
		}
	}

	return (mutex_unlock(&rw->mutex));
}


/* Return zero if write lock held by this thread, non-zero otherwise */
int
__nisdb_assert_wheld(__nisdb_rwlock_t *rw) {

	int	ret;


	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	if (rw->writer_count == 0 || rw->writer.id != pthread_self()) {
		ret = mutex_unlock(&rw->mutex);
		return ((ret == 0) ? -1 : ret);
	}

	/*
	 * We're holding the lock, so we should return zero. Since
	 * that's what mutex_unlock() does if it succeeds, we just
	 * return the value of mutex_unlock().
	 */
	return (mutex_unlock(&rw->mutex));
}


/* Return zero if read lock held by this thread, non-zero otherwise */
int
__nisdb_assert_rheld(__nisdb_rwlock_t *rw) {

	int		ret;
	pthread_t	myself = pthread_self();
	__nisdb_rl_t	*rr;


	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if (rw->force_write)
		return (__nisdb_assert_wheld(rw));

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	/* Write lock also OK */
	if (rw->writer_count > 0 && rw->writer.id == myself) {
		(void) mutex_unlock(&rw->mutex);
		return (0);
	}

	if (rw->reader_count == 0) {
		(void) mutex_unlock(&rw->mutex);
		return (EBUSY);
	}

	rr = &rw->reader;
	do {
		if (rr->id == myself) {
			(void) mutex_unlock(&rw->mutex);
			return (0);
		}
		rr = rr->next;
	} while (rr != 0);

	ret = mutex_unlock(&rw->mutex);
	return ((ret == 0) ? EBUSY : ret);
}


int
__nisdb_destroy_lock(__nisdb_rwlock_t *rw) {

	int		ret;
	pthread_t	myself = pthread_self();


	if (rw == 0) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		return (EFAULT);
	}

	if (rw->destroyed != 0)
		return (ESHUTDOWN);

	if ((ret = mutex_lock(&rw->mutex)) != 0)
		return (ret);

	if (rw->destroyed != 0) {
		(void) mutex_unlock(&rw->mutex);
		return (ESHUTDOWN);
	}

	/*
	 * Only proceed if if there are neither readers nor writers
	 * other than this thread. Also, no nested locks may be in
	 * effect.
	 */
	if (((rw->writer_count > 0 &&
	    (rw->writer.id != myself || rw->writer.count != 1)) ||
	    (rw->reader_count > 0 &&
	    !(rw->reader_count == 1 && rw->reader.id == myself &&
	    rw->reader.count == 1))) ||
	    (rw->writer_count > 0 && rw->reader_count > 0)) {
#ifdef	NISDB_MT_DEBUG
		abort();
#endif	/* NISDB_MT_DEBUG */
		(void) mutex_unlock(&rw->mutex);
		return (ENOLCK);
	}

	/*
	 * Mark lock destroyed, so that any thread waiting on the mutex
	 * will know what's what. Of course, this is a bit iffy, since
	 * we're probably being called from a destructor, and the structure
	 * where we live will soon cease to exist (i.e., be freed and
	 * perhaps re-used). Still, we can only do our best, and give
	 * those other threads the best chance possible.
	 */
	rw->destroyed++;

	return (mutex_unlock(&rw->mutex));
}

void
__nisdb_lock_report(__nisdb_rwlock_t *rw) {
	char		*myself = "__nisdb_lock_report";

	if (rw == 0) {
		printf("%s: NULL argument\n", myself);
		return;
	}

	if (rw->destroyed)
		printf("0x%x: DESTROYED\n", rw);

	printf("0x%x: Read locking %s\n",
		rw, rw->force_write ? "disallowed" : "allowed");

	if (rw->writer_count == 0)
		printf("0x%x: No writer\n", rw);
	else if (rw->writer_count == 1) {
		printf("0x%x: Write locked by %d, depth = %d\n",
			rw, rw->writer.id, rw->writer.count);
		if (rw->writer.wait)
			printf("0x%x:\tWriter blocked\n", rw);
	} else
		printf("0x%x: Invalid writer count = %d\n",
			rw, rw->writer_count);

	if (rw->reader_count == 0)
		printf("0x%x: No readers\n", rw);
	else {
		__nisdb_rl_t	*r;

		printf("0x%x: %d readers, %d blocked\n",
			rw, rw->reader_count, rw->reader_blocked);
		for (r = &rw->reader; r != 0; r = r->next) {
			printf("0x%x:\tthread %d, depth = %d%s\n",
				rw, r->id, r->count,
				(r->wait ? " (blocked)" : ""));
		}
	}
}
