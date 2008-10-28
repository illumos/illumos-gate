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

#include <sys/tzfile.h>
#include <sys/atomic.h>
#include <sys/kidmap.h>
#include <sys/time.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/string.h>
#include <smbsrv/mbuf.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_vops.h>

#include <smbsrv/smb_idmap.h>

#include <sys/sid.h>
#include <sys/priv_names.h>

#ifdef DEBUG
uint_t smb_tsd_key;
#endif

static boolean_t
smb_thread_continue_timedwait_locked(smb_thread_t *thread, int ticks);

time_t tzh_leapcnt = 0;

struct tm
*smb_gmtime_r(time_t *clock, struct tm *result);

time_t
smb_timegm(struct tm *tm);

struct	tm {
	int	tm_sec;
	int	tm_min;
	int	tm_hour;
	int	tm_mday;
	int	tm_mon;
	int	tm_year;
	int	tm_wday;
	int	tm_yday;
	int	tm_isdst;
};

static int days_in_month[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

int
smb_ascii_or_unicode_strlen(struct smb_request *sr, char *str)
{
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		return (mts_wcequiv_strlen(str));
	return (strlen(str));
}

int
smb_ascii_or_unicode_strlen_null(struct smb_request *sr, char *str)
{
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		return (mts_wcequiv_strlen(str) + 2);
	return (strlen(str) + 1);
}

int
smb_ascii_or_unicode_null_len(struct smb_request *sr)
{
	if (sr->smb_flg2 & SMB_FLAGS2_UNICODE)
		return (2);
	return (1);
}

int
smb_component_match(
    struct smb_request *sr,
    ino64_t fileid,
    struct smb_odir *od,
    smb_odir_context_t *pc)
{
	boolean_t ignore_case = SMB_TREE_IS_CASEINSENSITIVE(sr);

	return (smb_match_name(fileid, pc->dc_name, pc->dc_shortname,
	    pc->dc_name83, od->d_pattern, ignore_case));
}

int
smb_convert_unicode_wildcards(char *path)
{
	int	wildcards = 0;
	char	*ptr = path;
	char	nch;

	/*
	 * Special case "<" for "dir *."
	 */
	if (strcmp(path, "<") == 0) {
		return (1);
	}
	while (*ptr) {
		nch = *(ptr + 1);
		switch (*ptr) {
		case '*' : /* Count non-unicode wildcards while we're at it */
		case '?' :
			wildcards++;
			break;
		case '<' :
			if (nch == '.') {
				*(ptr++) = '*';
				wildcards++;
			}
			break;
		case '>' :
			*ptr = '?';
			wildcards++;
			break;
		case '\"' :
			*ptr = '.';
			break;
		}
		ptr++;
	}
	/* NT DOS wildcards... */
	if (strcmp(path, "????????.???") == 0) {
		(void) strcpy(path, "*");
	} else if (strncmp(path, "????????.", 9) == 0) {
		*path = '*';
		(void) strcpy(path+1, path+8);
	}

	return (wildcards);
}

/*
 * smb_is_dot_or_dotdot
 *
 * Use when checking for the "." and ".." entries in a directory.
 * Returns B_TRUE if the name is "." or "..". Otherwise returns B_FALSE.
 */
boolean_t
smb_is_dot_or_dotdot(const char *name)
{
	if (*name != '.')
		return (B_FALSE);

	if ((name[1] == 0) || (name[1] == '.' && name[2] == 0))
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * smb_sattr_check
 *
 * Check file attributes against a search attribute (sattr) mask.
 *
 * Normal files, which includes READONLY and ARCHIVE, always pass
 * this check.  If the DIRECTORY, HIDDEN or SYSTEM special attributes
 * are set then they must appear in the search mask.  The special
 * attributes are inclusive, i.e. all special attributes that appear
 * in sattr must also appear in the file attributes for the check to
 * pass.
 *
 * The following examples show how this works:
 *
 *		fileA:	READONLY
 *		fileB:	0 (no attributes = normal file)
 *		fileC:	READONLY, ARCHIVE
 *		fileD:	HIDDEN
 *		fileE:	READONLY, HIDDEN, SYSTEM
 *		dirA:	DIRECTORY
 *
 * search attribute: 0
 *		Returns: fileA, fileB and fileC.
 * search attribute: HIDDEN
 *		Returns: fileA, fileB, fileC and fileD.
 * search attribute: SYSTEM
 *		Returns: fileA, fileB and fileC.
 * search attribute: DIRECTORY
 *		Returns: fileA, fileB, fileC and dirA.
 * search attribute: HIDDEN and SYSTEM
 *		Returns: fileA, fileB, fileC, fileD and fileE.
 *
 * Returns true if the file and sattr match; otherwise, returns false.
 */
boolean_t
smb_sattr_check(smb_attr_t *ap, char *name, unsigned short sattr)
{
	if (name) {
		if (smb_is_dot_or_dotdot(name) &&
		    !(sattr & FILE_ATTRIBUTE_HIDDEN))
			return (B_FALSE);
	}

	if ((ap->sa_vattr.va_type == VDIR) &&
	    !(sattr & FILE_ATTRIBUTE_DIRECTORY))
		return (B_FALSE);

	if ((ap->sa_dosattr & FILE_ATTRIBUTE_HIDDEN) &&
	    !(sattr & FILE_ATTRIBUTE_HIDDEN))
		return (B_FALSE);

	if ((ap->sa_dosattr & FILE_ATTRIBUTE_SYSTEM) &&
	    !(sattr & FILE_ATTRIBUTE_SYSTEM))
		return (B_FALSE);

	return (B_TRUE);
}


/*
 * smb_stream_parse_name
 *
 * calling function is responsible for passing valid buffers with
 * adequate sizes.
 *
 *  path	    is a NULL terminated string which could be a
 *		    stream path. If it's a stream path it could be
 *		    in one of the following formats:
 *			  . path:stream
 *			  . path:stream:$DATA
 *		    unnamed stream is part of the path and there is
 *			    exactly one ':' in between the unamed and name
 *		    streams
 *
 *  u_stream_name   will contain the unamed stream portion upon
 *		    successful return.
 *		    this is the portion between last '\' and
 *		    the first ':'
 *
 *  stream_name	    will contain the named stream portion upon
 *		    successful return.
 *		    this is the portion between the first ':' and the
 *		    end of the 'name' string.
 *
 *  '::' - is a non-stream and is commonly used by Windows to designate
 *   the unamed stream in the form "::$DATA"
 *
 * on return the named stream always has a ":$DATA" appended if there
 * isn't one already
 *
 * Return Codes:
 *
 *	0	- given path doesn't contain any streams
 *	1	- given path had a stream
 */
int
smb_stream_parse_name(char *path, char *u_stream_name,
    char *stream_name)
{
	char *colonp;
	char *slashp;

	if (path == 0)
		return (0);

	/*
	 * if there is no colon in the path or it's the last char
	 * then it's not a stream name
	 */
	colonp = strchr(path, ':');
	if ((colonp == 0) || (*(colonp+1) == 0))
		return (0);

	/* "::" always means the unamed stream */
	if (strstr(path, "::"))
		return (0);

	if (stream_name) {
		/*
		 * stream name is the portion between ':' and the
		 * end of 'path' string (including the starting ':')
		 */
		(void) strcpy(stream_name, colonp);

		if (strstr(stream_name, ":$DATA") == 0)
			(void) strcat(stream_name, ":$DATA");
	}

	if (u_stream_name) {
		/*
		 * uname stream is the portion between last '\'
		 * and the ':'
		 */
		slashp = strrchr(path, '\\');
		slashp = (slashp == 0) ? path : slashp + 1;
		/*LINTED E_PTRDIFF_OVERFLOW*/
		(void) strlcpy(u_stream_name, slashp, colonp - slashp + 1);
	}
	return (1);
}

int
microtime(timestruc_t *tvp)
{
	tvp->tv_sec = gethrestime_sec();
	tvp->tv_nsec = 0;
	return (0);
}

int32_t
clock_get_milli_uptime()
{
	return (TICK_TO_MSEC(lbolt));
}

int /*ARGSUSED*/
smb_noop(void *p, size_t size, int foo)
{
	return (0);
}

/*
 * smb_idpool_increment
 *
 * This function increments the ID pool by doubling the current size. This
 * function assumes the caller entered the mutex of the pool.
 */
static int
smb_idpool_increment(
    smb_idpool_t	*pool)
{
	uint8_t		*new_pool;
	uint32_t	new_size;

	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);

	new_size = pool->id_size * 2;
	if (new_size <= SMB_IDPOOL_MAX_SIZE) {
		new_pool = kmem_alloc(new_size / 8, KM_NOSLEEP);
		if (new_pool) {
			bzero(new_pool, new_size / 8);
			bcopy(pool->id_pool, new_pool, pool->id_size / 8);
			kmem_free(pool->id_pool, pool->id_size / 8);
			pool->id_pool = new_pool;
			pool->id_free_counter += new_size - pool->id_size;
			pool->id_max_free_counter += new_size - pool->id_size;
			pool->id_size = new_size;
			pool->id_idx_msk = (new_size / 8) - 1;
			if (new_size >= SMB_IDPOOL_MAX_SIZE) {
				/* id -1 made unavailable */
				pool->id_pool[pool->id_idx_msk] = 0x80;
				pool->id_free_counter--;
				pool->id_max_free_counter--;
			}
			return (0);
		}
	}
	return (-1);
}

/*
 * smb_idpool_constructor
 *
 * This function initializes the pool structure provided.
 */
int
smb_idpool_constructor(
    smb_idpool_t	*pool)
{

	ASSERT(pool->id_magic != SMB_IDPOOL_MAGIC);

	pool->id_size = SMB_IDPOOL_MIN_SIZE;
	pool->id_idx_msk = (SMB_IDPOOL_MIN_SIZE / 8) - 1;
	pool->id_free_counter = SMB_IDPOOL_MIN_SIZE - 1;
	pool->id_max_free_counter = SMB_IDPOOL_MIN_SIZE - 1;
	pool->id_bit = 0x02;
	pool->id_bit_idx = 1;
	pool->id_idx = 0;
	pool->id_pool = (uint8_t *)kmem_alloc((SMB_IDPOOL_MIN_SIZE / 8),
	    KM_SLEEP);
	bzero(pool->id_pool, (SMB_IDPOOL_MIN_SIZE / 8));
	/* -1 id made unavailable */
	pool->id_pool[0] = 0x01;		/* id 0 made unavailable */
	mutex_init(&pool->id_mutex, NULL, MUTEX_DEFAULT, NULL);
	pool->id_magic = SMB_IDPOOL_MAGIC;
	return (0);
}

/*
 * smb_idpool_destructor
 *
 * This function tears down and frees the resources associated with the
 * pool provided.
 */
void
smb_idpool_destructor(
    smb_idpool_t	*pool)
{
	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);
	ASSERT(pool->id_free_counter == pool->id_max_free_counter);
	pool->id_magic = (uint32_t)~SMB_IDPOOL_MAGIC;
	mutex_destroy(&pool->id_mutex);
	kmem_free(pool->id_pool, (size_t)(pool->id_size / 8));
}

/*
 * smb_idpool_alloc
 *
 * This function allocates an ID from the pool provided.
 */
int
smb_idpool_alloc(
    smb_idpool_t	*pool,
    uint16_t		*id)
{
	uint32_t	i;
	uint8_t		bit;
	uint8_t		bit_idx;
	uint8_t		byte;

	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);

	mutex_enter(&pool->id_mutex);
	if ((pool->id_free_counter == 0) && smb_idpool_increment(pool)) {
		mutex_exit(&pool->id_mutex);
		return (-1);
	}

	i = pool->id_size;
	while (i) {
		bit = pool->id_bit;
		bit_idx = pool->id_bit_idx;
		byte = pool->id_pool[pool->id_idx];
		while (bit) {
			if (byte & bit) {
				bit = bit << 1;
				bit_idx++;
				continue;
			}
			pool->id_pool[pool->id_idx] |= bit;
			*id = (uint16_t)(pool->id_idx * 8 + (uint32_t)bit_idx);
			pool->id_free_counter--;
			pool->id_bit = bit;
			pool->id_bit_idx = bit_idx;
			mutex_exit(&pool->id_mutex);
			return (0);
		}
		pool->id_bit = 1;
		pool->id_bit_idx = 0;
		pool->id_idx++;
		pool->id_idx &= pool->id_idx_msk;
		--i;
	}
	/*
	 * This section of code shouldn't be reached. If there are IDs
	 * available and none could be found there's a problem.
	 */
	ASSERT(0);
	mutex_exit(&pool->id_mutex);
	return (-1);
}

/*
 * smb_idpool_free
 *
 * This function frees the ID provided.
 */
void
smb_idpool_free(
    smb_idpool_t	*pool,
    uint16_t		id)
{
	ASSERT(pool->id_magic == SMB_IDPOOL_MAGIC);
	ASSERT(id != 0);
	ASSERT(id != 0xFFFF);

	mutex_enter(&pool->id_mutex);
	if (pool->id_pool[id >> 3] & (1 << (id & 7))) {
		pool->id_pool[id >> 3] &= ~(1 << (id & 7));
		pool->id_free_counter++;
		ASSERT(pool->id_free_counter <= pool->id_max_free_counter);
		mutex_exit(&pool->id_mutex);
		return;
	}
	/* Freeing a free ID. */
	ASSERT(0);
	mutex_exit(&pool->id_mutex);
}

/*
 * smb_llist_constructor
 *
 * This function initializes a locked list.
 */
void
smb_llist_constructor(
    smb_llist_t	*ll,
    size_t	size,
    size_t	offset)
{
	rw_init(&ll->ll_lock, NULL, RW_DEFAULT, NULL);
	list_create(&ll->ll_list, size, offset);
	ll->ll_count = 0;
	ll->ll_wrop = 0;
}

/*
 * smb_llist_destructor
 *
 * This function destroys a locked list.
 */
void
smb_llist_destructor(
    smb_llist_t	*ll)
{
	ASSERT(ll->ll_count == 0);

	rw_destroy(&ll->ll_lock);
	list_destroy(&ll->ll_list);
}

/*
 * smb_llist_upgrade
 *
 * This function tries to upgrade the lock of the locked list. It assumes the
 * locked has already been entered in RW_READER mode. It first tries using the
 * Solaris function rw_tryupgrade(). If that call fails the lock is released
 * and reentered in RW_WRITER mode. In that last case a window is opened during
 * which the contents of the list may have changed. The return code indicates
 * whether or not the list was modified when the lock was exited.
 */
int smb_llist_upgrade(
    smb_llist_t *ll)
{
	uint64_t	wrop;

	if (rw_tryupgrade(&ll->ll_lock) != 0) {
		return (0);
	}
	wrop = ll->ll_wrop;
	rw_exit(&ll->ll_lock);
	rw_enter(&ll->ll_lock, RW_WRITER);
	return (wrop != ll->ll_wrop);
}

/*
 * smb_llist_insert_head
 *
 * This function inserts the object passed a the beginning of the list. This
 * function assumes the lock of the list has already been entered.
 */
void
smb_llist_insert_head(
    smb_llist_t	*ll,
    void	*obj)
{
	list_insert_head(&ll->ll_list, obj);
	++ll->ll_wrop;
	++ll->ll_count;
}

/*
 * smb_llist_insert_tail
 *
 * This function appends to the object passed to the list. This function assumes
 * the lock of the list has already been entered.
 *
 */
void
smb_llist_insert_tail(
    smb_llist_t	*ll,
    void	*obj)
{
	list_insert_tail(&ll->ll_list, obj);
	++ll->ll_wrop;
	++ll->ll_count;
}

/*
 * smb_llist_remove
 *
 * This function removes the object passed from the list. This function assumes
 * the lock of the list has already been entered.
 */
void
smb_llist_remove(
    smb_llist_t	*ll,
    void	*obj)
{
	list_remove(&ll->ll_list, obj);
	++ll->ll_wrop;
	--ll->ll_count;
}

/*
 * smb_llist_get_count
 *
 * This function returns the number of elements in the specified list.
 */
uint32_t
smb_llist_get_count(
    smb_llist_t *ll)
{
	return (ll->ll_count);
}

/*
 * smb_slist_constructor
 *
 * Synchronized list constructor.
 */
void
smb_slist_constructor(
    smb_slist_t	*sl,
    size_t	size,
    size_t	offset)
{
	mutex_init(&sl->sl_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sl->sl_cv, NULL, CV_DEFAULT, NULL);
	list_create(&sl->sl_list, size, offset);
	sl->sl_count = 0;
	sl->sl_waiting = B_FALSE;
}

/*
 * smb_slist_destructor
 *
 * Synchronized list destructor.
 */
void
smb_slist_destructor(
    smb_slist_t	*sl)
{
	ASSERT(sl->sl_count == 0);

	mutex_destroy(&sl->sl_mutex);
	cv_destroy(&sl->sl_cv);
	list_destroy(&sl->sl_list);
}

/*
 * smb_slist_insert_head
 *
 * This function inserts the object passed a the beginning of the list.
 */
void
smb_slist_insert_head(
    smb_slist_t	*sl,
    void	*obj)
{
	mutex_enter(&sl->sl_mutex);
	list_insert_head(&sl->sl_list, obj);
	++sl->sl_count;
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_slist_insert_tail
 *
 * This function appends the object passed to the list.
 */
void
smb_slist_insert_tail(
    smb_slist_t	*sl,
    void	*obj)
{
	mutex_enter(&sl->sl_mutex);
	list_insert_tail(&sl->sl_list, obj);
	++sl->sl_count;
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_llist_remove
 *
 * This function removes the object passed by the caller from the list.
 */
void
smb_slist_remove(
    smb_slist_t	*sl,
    void	*obj)
{
	mutex_enter(&sl->sl_mutex);
	list_remove(&sl->sl_list, obj);
	if ((--sl->sl_count == 0) && (sl->sl_waiting)) {
		sl->sl_waiting = B_FALSE;
		cv_broadcast(&sl->sl_cv);
	}
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_slist_move_tail
 *
 * This function transfers all the contents of the synchronized list to the
 * list_t provided. It returns the number of objects transferred.
 */
uint32_t
smb_slist_move_tail(
    list_t	*lst,
    smb_slist_t	*sl)
{
	uint32_t	rv;

	mutex_enter(&sl->sl_mutex);
	rv = sl->sl_count;
	if (sl->sl_count) {
		list_move_tail(lst, &sl->sl_list);
		sl->sl_count = 0;
		if (sl->sl_waiting) {
			sl->sl_waiting = B_FALSE;
			cv_broadcast(&sl->sl_cv);
		}
	}
	mutex_exit(&sl->sl_mutex);
	return (rv);
}

/*
 * smb_slist_obj_move
 *
 * This function moves an object from one list to the end of the other list. It
 * assumes the mutex of each list has been entered.
 */
void
smb_slist_obj_move(
    smb_slist_t	*dst,
    smb_slist_t	*src,
    void	*obj)
{
	ASSERT(dst->sl_list.list_offset == src->sl_list.list_offset);
	ASSERT(dst->sl_list.list_size == src->sl_list.list_size);

	list_remove(&src->sl_list, obj);
	list_insert_tail(&dst->sl_list, obj);
	dst->sl_count++;
	src->sl_count--;
	if ((src->sl_count == 0) && (src->sl_waiting)) {
		src->sl_waiting = B_FALSE;
		cv_broadcast(&src->sl_cv);
	}
}

/*
 * smb_slist_wait_for_empty
 *
 * This function waits for a list to be emptied.
 */
void
smb_slist_wait_for_empty(
    smb_slist_t	*sl)
{
	mutex_enter(&sl->sl_mutex);
	while (sl->sl_count) {
		sl->sl_waiting = B_TRUE;
		cv_wait(&sl->sl_cv, &sl->sl_mutex);
	}
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_slist_exit
 *
 * This function exits the muetx of the list and signal the condition variable
 * if the list is empty.
 */
void
smb_slist_exit(smb_slist_t *sl)
{
	if ((sl->sl_count == 0) && (sl->sl_waiting)) {
		sl->sl_waiting = B_FALSE;
		cv_broadcast(&sl->sl_cv);
	}
	mutex_exit(&sl->sl_mutex);
}

/*
 * smb_thread_entry_point
 *
 * Common entry point for all the threads created through smb_thread_start. The
 * state of teh thread is set to "running" at the beginning and moved to
 * "exiting" just before calling thread_exit(). The condition variable is
 *  also signaled.
 */
static void
smb_thread_entry_point(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);
	mutex_enter(&thread->sth_mtx);
	ASSERT(thread->sth_state == SMB_THREAD_STATE_STARTING);
	thread->sth_th = curthread;
	thread->sth_did = thread->sth_th->t_did;

	if (!thread->sth_kill) {
		thread->sth_state = SMB_THREAD_STATE_RUNNING;
		cv_signal(&thread->sth_cv);
		mutex_exit(&thread->sth_mtx);
		thread->sth_ep(thread, thread->sth_ep_arg);
		mutex_enter(&thread->sth_mtx);
	}
	thread->sth_th = NULL;
	thread->sth_state = SMB_THREAD_STATE_EXITING;
	cv_broadcast(&thread->sth_cv);
	mutex_exit(&thread->sth_mtx);
	thread_exit();
}

/*
 * smb_thread_init
 */
void
smb_thread_init(
    smb_thread_t	*thread,
    char		*name,
    smb_thread_ep_t	ep,
    void		*ep_arg,
    smb_thread_aw_t	aw,
    void		*aw_arg)
{
	ASSERT(thread->sth_magic != SMB_THREAD_MAGIC);

	bzero(thread, sizeof (*thread));

	(void) strlcpy(thread->sth_name, name, sizeof (thread->sth_name));
	thread->sth_ep = ep;
	thread->sth_ep_arg = ep_arg;
	thread->sth_aw = aw;
	thread->sth_aw_arg = aw_arg;
	thread->sth_state = SMB_THREAD_STATE_EXITED;
	mutex_init(&thread->sth_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&thread->sth_cv, NULL, CV_DEFAULT, NULL);
	thread->sth_magic = SMB_THREAD_MAGIC;
}

/*
 * smb_thread_destroy
 */
void
smb_thread_destroy(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);
	ASSERT(thread->sth_state == SMB_THREAD_STATE_EXITED);
	thread->sth_magic = 0;
	mutex_destroy(&thread->sth_mtx);
	cv_destroy(&thread->sth_cv);
}

/*
 * smb_thread_start
 *
 * This function starts a thread with the parameters provided. It waits until
 * the state of the thread has been moved to running.
 */
/*ARGSUSED*/
int
smb_thread_start(
    smb_thread_t	*thread)
{
	int		rc = 0;
	kthread_t	*tmpthread;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_EXITED:
		thread->sth_state = SMB_THREAD_STATE_STARTING;
		mutex_exit(&thread->sth_mtx);
		tmpthread = thread_create(NULL, 0, smb_thread_entry_point,
		    thread, 0, &p0, TS_RUN, minclsyspri);
		ASSERT(tmpthread != NULL);
		mutex_enter(&thread->sth_mtx);
		while (thread->sth_state == SMB_THREAD_STATE_STARTING)
			cv_wait(&thread->sth_cv, &thread->sth_mtx);
		if (thread->sth_state != SMB_THREAD_STATE_RUNNING)
			rc = -1;
		break;
	default:
		ASSERT(0);
		rc = -1;
		break;
	}
	mutex_exit(&thread->sth_mtx);
	return (rc);
}

/*
 * smb_thread_stop
 *
 * This function signals a thread to kill itself and waits until the "exiting"
 * state has been reached.
 */
void
smb_thread_stop(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_RUNNING:
	case SMB_THREAD_STATE_STARTING:
		if (!thread->sth_kill) {
			thread->sth_kill = B_TRUE;
			if (thread->sth_aw)
				thread->sth_aw(thread, thread->sth_aw_arg);
			cv_broadcast(&thread->sth_cv);
			while (thread->sth_state != SMB_THREAD_STATE_EXITING)
				cv_wait(&thread->sth_cv, &thread->sth_mtx);
			mutex_exit(&thread->sth_mtx);
			thread_join(thread->sth_did);
			mutex_enter(&thread->sth_mtx);
			thread->sth_state = SMB_THREAD_STATE_EXITED;
			thread->sth_did = 0;
			thread->sth_kill = B_FALSE;
			cv_broadcast(&thread->sth_cv);
			break;
		}
		/*FALLTHRU*/

	case SMB_THREAD_STATE_EXITING:
		if (thread->sth_kill) {
			while (thread->sth_state != SMB_THREAD_STATE_EXITED)
				cv_wait(&thread->sth_cv, &thread->sth_mtx);
		} else {
			thread->sth_state = SMB_THREAD_STATE_EXITED;
			thread->sth_did = 0;
		}
		break;

	case SMB_THREAD_STATE_EXITED:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&thread->sth_mtx);
}

/*
 * smb_thread_signal
 *
 * This function signals a thread.
 */
void
smb_thread_signal(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_RUNNING:
		if (thread->sth_aw)
			thread->sth_aw(thread, thread->sth_aw_arg);
		cv_signal(&thread->sth_cv);
		break;

	default:
		break;
	}
	mutex_exit(&thread->sth_mtx);
}

boolean_t
smb_thread_continue(smb_thread_t *thread)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	result = smb_thread_continue_timedwait_locked(thread, 0);
	mutex_exit(&thread->sth_mtx);

	return (result);
}

boolean_t
smb_thread_continue_nowait(smb_thread_t *thread)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	/*
	 * Setting ticks=-1 requests a non-blocking check.  We will
	 * still block if the thread is in "suspend" state.
	 */
	result = smb_thread_continue_timedwait_locked(thread, -1);
	mutex_exit(&thread->sth_mtx);

	return (result);
}

boolean_t
smb_thread_continue_timedwait(smb_thread_t *thread, int seconds)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	result = smb_thread_continue_timedwait_locked(thread,
	    SEC_TO_TICK(seconds));
	mutex_exit(&thread->sth_mtx);

	return (result);
}

/*
 * smb_thread_continue_timedwait_locked
 *
 * Internal only.  Ticks==-1 means don't block, Ticks == 0 means wait
 * indefinitely
 */
static boolean_t
smb_thread_continue_timedwait_locked(smb_thread_t *thread, int ticks)
{
	boolean_t	result;
	clock_t		finish_time = lbolt + ticks;

	/* -1 means don't block */
	if (ticks != -1 && !thread->sth_kill) {
		if (ticks == 0) {
			cv_wait(&thread->sth_cv, &thread->sth_mtx);
		} else {
			(void) cv_timedwait(&thread->sth_cv, &thread->sth_mtx,
			    finish_time);
		}
	}
	result = (thread->sth_kill == 0);

	return (result);
}

void
smb_thread_set_awaken(smb_thread_t *thread, smb_thread_aw_t new_aw_fn,
    void *new_aw_arg)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	thread->sth_aw = new_aw_fn;
	thread->sth_aw_arg = new_aw_arg;
	mutex_exit(&thread->sth_mtx);
}

/*
 * smb_rwx_init
 */
void
smb_rwx_init(
    smb_rwx_t	*rwx)
{
	bzero(rwx, sizeof (smb_rwx_t));
	cv_init(&rwx->rwx_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&rwx->rwx_mutex, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&rwx->rwx_lock, NULL, RW_DEFAULT, NULL);
}

/*
 * smb_rwx_destroy
 */
void
smb_rwx_destroy(
    smb_rwx_t	*rwx)
{
	mutex_destroy(&rwx->rwx_mutex);
	cv_destroy(&rwx->rwx_cv);
	rw_destroy(&rwx->rwx_lock);
}

/*
 * smb_rwx_rwexit
 */
void
smb_rwx_rwexit(
    smb_rwx_t	*rwx)
{
	if (rw_write_held(&rwx->rwx_lock)) {
		ASSERT(rw_owner(&rwx->rwx_lock) == curthread);
		mutex_enter(&rwx->rwx_mutex);
		if (rwx->rwx_waiting) {
			rwx->rwx_waiting = B_FALSE;
			cv_broadcast(&rwx->rwx_cv);
		}
		mutex_exit(&rwx->rwx_mutex);
	}
	rw_exit(&rwx->rwx_lock);
}

/*
 * smb_rwx_rwupgrade
 */
krw_t
smb_rwx_rwupgrade(
    smb_rwx_t	*rwx)
{
	if (rw_write_held(&rwx->rwx_lock)) {
		ASSERT(rw_owner(&rwx->rwx_lock) == curthread);
		return (RW_WRITER);
	}
	if (!rw_tryupgrade(&rwx->rwx_lock)) {
		rw_exit(&rwx->rwx_lock);
		rw_enter(&rwx->rwx_lock, RW_WRITER);
	}
	return (RW_READER);
}

/*
 * smb_rwx_rwrestore
 */
void
smb_rwx_rwdowngrade(
    smb_rwx_t	*rwx,
    krw_t	mode)
{
	ASSERT(rw_write_held(&rwx->rwx_lock));
	ASSERT(rw_owner(&rwx->rwx_lock) == curthread);

	if (mode == RW_WRITER) {
		return;
	}
	ASSERT(mode == RW_READER);
	mutex_enter(&rwx->rwx_mutex);
	if (rwx->rwx_waiting) {
		rwx->rwx_waiting = B_FALSE;
		cv_broadcast(&rwx->rwx_cv);
	}
	mutex_exit(&rwx->rwx_mutex);
	rw_downgrade(&rwx->rwx_lock);
}

/*
 * smb_rwx_wait
 *
 * This function assumes the smb_rwx lock was enter in RW_READER or RW_WRITER
 * mode. It will:
 *
 *	1) release the lock and save its current mode.
 *	2) wait until the condition variable is signaled. This can happen for
 *	   2 reasons: When a writer releases the lock or when the time out (if
 *	   provided) expires.
 *	3) re-acquire the lock in the mode saved in (1).
 */
int
smb_rwx_rwwait(
    smb_rwx_t	*rwx,
    clock_t	timeout)
{
	int	rc;
	krw_t	mode;

	mutex_enter(&rwx->rwx_mutex);
	rwx->rwx_waiting = B_TRUE;
	mutex_exit(&rwx->rwx_mutex);

	if (rw_write_held(&rwx->rwx_lock)) {
		ASSERT(rw_owner(&rwx->rwx_lock) == curthread);
		mode = RW_WRITER;
	} else {
		ASSERT(rw_read_held(&rwx->rwx_lock));
		mode = RW_READER;
	}
	rw_exit(&rwx->rwx_lock);

	mutex_enter(&rwx->rwx_mutex);
	if (rwx->rwx_waiting) {
		if (timeout == -1) {
			rc = 1;
			cv_wait(&rwx->rwx_cv, &rwx->rwx_mutex);
		} else {
			rc = cv_timedwait(&rwx->rwx_cv, &rwx->rwx_mutex,
			    lbolt + timeout);
		}
	}
	mutex_exit(&rwx->rwx_mutex);

	rw_enter(&rwx->rwx_lock, mode);
	return (rc);
}

/*
 * SMB ID mapping
 *
 * Solaris ID mapping service (aka Winchester) works with domain SIDs
 * and RIDs where domain SIDs are in string format. CIFS service works
 * with binary SIDs understandable by CIFS clients. A layer of SMB ID
 * mapping functions are implemeted to hide the SID conversion details
 * and also hide the handling of array of batch mapping requests.
 *
 * IMPORTANT NOTE The Winchester API requires a zone. Because CIFS server
 * currently only runs in the global zone the global zone is specified.
 * This needs to be fixed when the CIFS server supports zones.
 */

static int smb_idmap_batch_binsid(smb_idmap_batch_t *sib);

/*
 * smb_idmap_getid
 *
 * Maps the given Windows SID to a Solaris ID using the
 * simple mapping API.
 */
idmap_stat
smb_idmap_getid(smb_sid_t *sid, uid_t *id, int *idtype)
{
	smb_idmap_t sim;
	char sidstr[SMB_SID_STRSZ];

	smb_sid_tostr(sid, sidstr);
	if (smb_sid_splitstr(sidstr, &sim.sim_rid) != 0)
		return (IDMAP_ERR_SID);
	sim.sim_domsid = sidstr;
	sim.sim_id = id;

	switch (*idtype) {
	case SMB_IDMAP_USER:
		sim.sim_stat = kidmap_getuidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id);
		break;

	case SMB_IDMAP_GROUP:
		sim.sim_stat = kidmap_getgidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id);
		break;

	case SMB_IDMAP_UNKNOWN:
		sim.sim_stat = kidmap_getpidbysid(global_zone, sim.sim_domsid,
		    sim.sim_rid, sim.sim_id, &sim.sim_idtype);
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	*idtype = sim.sim_idtype;

	return (sim.sim_stat);
}

/*
 * smb_idmap_getsid
 *
 * Maps the given Solaris ID to a Windows SID using the
 * simple mapping API.
 */
idmap_stat
smb_idmap_getsid(uid_t id, int idtype, smb_sid_t **sid)
{
	smb_idmap_t sim;

	switch (idtype) {
	case SMB_IDMAP_USER:
		sim.sim_stat = kidmap_getsidbyuid(global_zone, id,
		    (const char **)&sim.sim_domsid, &sim.sim_rid);
		break;

	case SMB_IDMAP_GROUP:
		sim.sim_stat = kidmap_getsidbygid(global_zone, id,
		    (const char **)&sim.sim_domsid, &sim.sim_rid);
		break;

	case SMB_IDMAP_EVERYONE:
		/* Everyone S-1-1-0 */
		sim.sim_domsid = "S-1-1";
		sim.sim_rid = 0;
		sim.sim_stat = IDMAP_SUCCESS;
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	if (sim.sim_stat != IDMAP_SUCCESS)
		return (sim.sim_stat);

	if (sim.sim_domsid == NULL)
		return (IDMAP_ERR_NOMAPPING);

	sim.sim_sid = smb_sid_fromstr(sim.sim_domsid);
	if (sim.sim_sid == NULL)
		return (IDMAP_ERR_INTERNAL);

	*sid = smb_sid_splice(sim.sim_sid, sim.sim_rid);
	smb_sid_free(sim.sim_sid);
	if (*sid == NULL)
		sim.sim_stat = IDMAP_ERR_INTERNAL;

	return (sim.sim_stat);
}

/*
 * smb_idmap_batch_create
 *
 * Creates and initializes the context for batch ID mapping.
 */
idmap_stat
smb_idmap_batch_create(smb_idmap_batch_t *sib, uint16_t nmap, int flags)
{
	ASSERT(sib);

	bzero(sib, sizeof (smb_idmap_batch_t));

	sib->sib_idmaph = kidmap_get_create(global_zone);

	sib->sib_flags = flags;
	sib->sib_nmap = nmap;
	sib->sib_size = nmap * sizeof (smb_idmap_t);
	sib->sib_maps = kmem_zalloc(sib->sib_size, KM_SLEEP);

	return (IDMAP_SUCCESS);
}

/*
 * smb_idmap_batch_destroy
 *
 * Frees the batch ID mapping context.
 * If ID mapping is Solaris -> Windows it frees memories
 * allocated for binary SIDs.
 */
void
smb_idmap_batch_destroy(smb_idmap_batch_t *sib)
{
	char *domsid;
	int i;

	ASSERT(sib);
	ASSERT(sib->sib_maps);

	if (sib->sib_idmaph)
		kidmap_get_destroy(sib->sib_idmaph);

	if (sib->sib_flags & SMB_IDMAP_ID2SID) {
		/*
		 * SIDs are allocated only when mapping
		 * UID/GID to SIDs
		 */
		for (i = 0; i < sib->sib_nmap; i++)
			smb_sid_free(sib->sib_maps[i].sim_sid);
	} else if (sib->sib_flags & SMB_IDMAP_SID2ID) {
		/*
		 * SID prefixes are allocated only when mapping
		 * SIDs to UID/GID
		 */
		for (i = 0; i < sib->sib_nmap; i++) {
			domsid = sib->sib_maps[i].sim_domsid;
			if (domsid)
				kmem_free(domsid, strlen(domsid) + 1);
		}
	}

	if (sib->sib_size && sib->sib_maps)
		kmem_free(sib->sib_maps, sib->sib_size);
}

/*
 * smb_idmap_batch_getid
 *
 * Queue a request to map the given SID to a UID or GID.
 *
 * sim->sim_id should point to variable that's supposed to
 * hold the returned UID/GID. This needs to be setup by caller
 * of this function.
 *
 * If requested ID type is known, it's passed as 'idtype',
 * if it's unknown it'll be returned in sim->sim_idtype.
 */
idmap_stat
smb_idmap_batch_getid(idmap_get_handle_t *idmaph, smb_idmap_t *sim,
    smb_sid_t *sid, int idtype)
{
	char strsid[SMB_SID_STRSZ];
	idmap_stat idm_stat;

	ASSERT(idmaph);
	ASSERT(sim);
	ASSERT(sid);

	smb_sid_tostr(sid, strsid);
	if (smb_sid_splitstr(strsid, &sim->sim_rid) != 0)
		return (IDMAP_ERR_SID);
	sim->sim_domsid = smb_kstrdup(strsid, strlen(strsid) + 1);

	switch (idtype) {
	case SMB_IDMAP_USER:
		idm_stat = kidmap_batch_getuidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_stat);
		break;

	case SMB_IDMAP_GROUP:
		idm_stat = kidmap_batch_getgidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_stat);
		break;

	case SMB_IDMAP_UNKNOWN:
		idm_stat = kidmap_batch_getpidbysid(idmaph, sim->sim_domsid,
		    sim->sim_rid, sim->sim_id, &sim->sim_idtype,
		    &sim->sim_stat);
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	return (idm_stat);
}

/*
 * smb_idmap_batch_getsid
 *
 * Queue a request to map the given UID/GID to a SID.
 *
 * sim->sim_domsid and sim->sim_rid will contain the mapping
 * result upon successful process of the batched request.
 */
idmap_stat
smb_idmap_batch_getsid(idmap_get_handle_t *idmaph, smb_idmap_t *sim,
    uid_t id, int idtype)
{
	idmap_stat idm_stat;

	switch (idtype) {
	case SMB_IDMAP_USER:
		idm_stat = kidmap_batch_getsidbyuid(idmaph, id,
		    (const char **)&sim->sim_domsid, &sim->sim_rid,
		    &sim->sim_stat);
		break;

	case SMB_IDMAP_GROUP:
		idm_stat = kidmap_batch_getsidbygid(idmaph, id,
		    (const char **)&sim->sim_domsid, &sim->sim_rid,
		    &sim->sim_stat);
		break;

	case SMB_IDMAP_EVERYONE:
		/* Everyone S-1-1-0 */
		sim->sim_domsid = "S-1-1";
		sim->sim_rid = 0;
		sim->sim_stat = IDMAP_SUCCESS;
		idm_stat = IDMAP_SUCCESS;
		break;

	default:
		ASSERT(0);
		return (IDMAP_ERR_ARG);
	}

	return (idm_stat);
}

/*
 * smb_idmap_batch_binsid
 *
 * Convert sidrids to binary sids
 *
 * Returns 0 if successful and non-zero upon failure.
 */
static int
smb_idmap_batch_binsid(smb_idmap_batch_t *sib)
{
	smb_sid_t *sid;
	smb_idmap_t *sim;
	int i;

	if (sib->sib_flags & SMB_IDMAP_SID2ID)
		/* This operation is not required */
		return (0);

	sim = sib->sib_maps;
	for (i = 0; i < sib->sib_nmap; sim++, i++) {
		ASSERT(sim->sim_domsid);
		if (sim->sim_domsid == NULL)
			return (1);

		if ((sid = smb_sid_fromstr(sim->sim_domsid)) == NULL)
			return (1);

		sim->sim_sid = smb_sid_splice(sid, sim->sim_rid);
		smb_sid_free(sid);
	}

	return (0);
}

/*
 * smb_idmap_batch_getmappings
 *
 * trigger ID mapping service to get the mappings for queued
 * requests.
 *
 * Checks the result of all the queued requests.
 * If this is a Solaris -> Windows mapping it generates
 * binary SIDs from returned (domsid, rid) pairs.
 */
idmap_stat
smb_idmap_batch_getmappings(smb_idmap_batch_t *sib)
{
	idmap_stat idm_stat = IDMAP_SUCCESS;
	int i;

	idm_stat = kidmap_get_mappings(sib->sib_idmaph);
	if (idm_stat != IDMAP_SUCCESS)
		return (idm_stat);

	/*
	 * Check the status for all the queued requests
	 */
	for (i = 0; i < sib->sib_nmap; i++) {
		if (sib->sib_maps[i].sim_stat != IDMAP_SUCCESS)
			return (sib->sib_maps[i].sim_stat);
	}

	if (smb_idmap_batch_binsid(sib) != 0)
		idm_stat = IDMAP_ERR_OTHER;

	return (idm_stat);
}

uint64_t
unix_to_nt_time(timestruc_t *unix_time)
{
	uint64_t nt_time;

	nt_time = unix_time->tv_sec;
	nt_time *= 10000000;  /* seconds to 100ns */
	nt_time += unix_time->tv_nsec / 100;
	return (nt_time + NT_TIME_BIAS);
}

uint32_t
nt_to_unix_time(uint64_t nt_time, timestruc_t *unix_time)
{
	uint32_t seconds;

	nt_time -= NT_TIME_BIAS;
	seconds = nt_time / 10000000;
	if (unix_time) {
		unix_time->tv_sec = seconds;
		unix_time->tv_nsec = (nt_time  % 10000000) * 100;
	}
	return (seconds);
}

/*
 * smb_dos_to_ux_time
 *
 * Convert SMB_DATE & SMB_TIME values to a unix timestamp.
 *
 * A date/time field of 0 means that that server file system
 * assigned value need not be changed. The behaviour when the
 * date/time field is set to -1 is not documented but is
 * generally treated like 0.
 * If date or time is 0 or -1 the unix time is returned as 0
 * so that the caller can identify and handle this special case.
 */
int32_t
smb_dos_to_ux_time(int16_t date, int16_t time)
{
	struct tm	atm;

	if (((date == 0) || (time == 0)) ||
	    ((date == -1) || (time == -1))) {
		return (0);
	}

	atm.tm_year = ((date >>  9) & 0x3F) + 80;
	atm.tm_mon  = ((date >>  5) & 0x0F) - 1;
	atm.tm_mday = ((date >>  0) & 0x1F);
	atm.tm_hour = ((time >> 11) & 0x1F);
	atm.tm_min  = ((time >>  5) & 0x3F);
	atm.tm_sec  = ((time >>  0) & 0x1F) << 1;

	return (smb_timegm(&atm));
}

int32_t
smb_ux_to_dos_time(int32_t ux_time, int16_t *date_p, int16_t *time_p)
{
	struct tm	atm;
	int		i;
	time_t		tmp_time;

	tmp_time = (time_t)ux_time;
	(void) smb_gmtime_r(&tmp_time, &atm);

	if (date_p) {
		i = 0;
		i += atm.tm_year - 80;
		i <<= 4;
		i += atm.tm_mon + 1;
		i <<= 5;
		i += atm.tm_mday;

		*date_p = (short)i;
	}
	if (time_p) {
		i = 0;
		i += atm.tm_hour;
		i <<= 6;
		i += atm.tm_min;
		i <<= 5;
		i += atm.tm_sec >> 1;

		*time_p = (short)i;
	}
	return (ux_time);
}


/*
 * smb_gmtime_r
 *
 * Thread-safe version of smb_gmtime. Returns a null pointer if either
 * input parameter is a null pointer. Otherwise returns a pointer
 * to result.
 *
 * Day of the week calculation: the Epoch was a thursday.
 *
 * There are no timezone corrections so tm_isdst and tm_gmtoff are
 * always zero, and the zone is always WET.
 */
struct tm *
smb_gmtime_r(time_t *clock, struct tm *result)
{
	time_t tsec;
	int year;
	int month;
	int sec_per_month;

	if (clock == 0 || result == 0)
		return (0);

	bzero(result, sizeof (struct tm));
	tsec = *clock;
	tsec -= tzh_leapcnt;

	result->tm_wday = tsec / SECSPERDAY;
	result->tm_wday = (result->tm_wday + TM_THURSDAY) % DAYSPERWEEK;

	year = EPOCH_YEAR;
	while (tsec >= (isleap(year) ? (SECSPERDAY * DAYSPERLYEAR) :
	    (SECSPERDAY * DAYSPERNYEAR))) {
		if (isleap(year))
			tsec -= SECSPERDAY * DAYSPERLYEAR;
		else
			tsec -= SECSPERDAY * DAYSPERNYEAR;

		++year;
	}

	result->tm_year = year - TM_YEAR_BASE;
	result->tm_yday = tsec / SECSPERDAY;

	for (month = TM_JANUARY; month <= TM_DECEMBER; ++month) {
		sec_per_month = days_in_month[month] * SECSPERDAY;

		if (month == TM_FEBRUARY && isleap(year))
			sec_per_month += SECSPERDAY;

		if (tsec < sec_per_month)
			break;

		tsec -= sec_per_month;
	}

	result->tm_mon = month;
	result->tm_mday = (tsec / SECSPERDAY) + 1;
	tsec %= SECSPERDAY;
	result->tm_sec = tsec % 60;
	tsec /= 60;
	result->tm_min = tsec % 60;
	tsec /= 60;
	result->tm_hour = (int)tsec;

	return (result);
}


/*
 * smb_timegm
 *
 * Converts the broken-down time in tm to a time value, i.e. the number
 * of seconds since the Epoch (00:00:00 UTC, January 1, 1970). This is
 * not a POSIX or ANSI function. Per the man page, the input values of
 * tm_wday and tm_yday are ignored and, as the input data is assumed to
 * represent GMT, we force tm_isdst and tm_gmtoff to 0.
 *
 * Before returning the clock time, we use smb_gmtime_r to set up tm_wday
 * and tm_yday, and bring the other fields within normal range. I don't
 * think this is really how it should be done but it's convenient for
 * now.
 */
time_t
smb_timegm(struct tm *tm)
{
	time_t tsec;
	int dd;
	int mm;
	int yy;
	int year;

	if (tm == 0)
		return (-1);

	year = tm->tm_year + TM_YEAR_BASE;
	tsec = tzh_leapcnt;

	for (yy = EPOCH_YEAR; yy < year; ++yy) {
		if (isleap(yy))
			tsec += SECSPERDAY * DAYSPERLYEAR;
		else
			tsec += SECSPERDAY * DAYSPERNYEAR;
	}

	for (mm = TM_JANUARY; mm < tm->tm_mon; ++mm) {
		dd = days_in_month[mm] * SECSPERDAY;

		if (mm == TM_FEBRUARY && isleap(year))
			dd += SECSPERDAY;

		tsec += dd;
	}

	tsec += (tm->tm_mday - 1) * SECSPERDAY;
	tsec += tm->tm_sec;
	tsec += tm->tm_min * SECSPERMIN;
	tsec += tm->tm_hour * SECSPERHOUR;

	tm->tm_isdst = 0;
	(void) smb_gmtime_r(&tsec, tm);
	return (tsec);
}

#ifdef	DEBUG
uint32_t	smb_audit_flags = SMB_AUDIT_NODE;
#else
uint32_t	smb_audit_flags = 0;
#endif

void
smb_audit_buf_node_create(smb_node_t *node)
{
	smb_audit_buf_node_t	*abn;

	if (smb_audit_flags & SMB_AUDIT_NODE) {
		abn = kmem_zalloc(sizeof (smb_audit_buf_node_t), KM_SLEEP);
		abn->anb_max_index = SMB_AUDIT_BUF_MAX_REC - 1;
		node->n_audit_buf = abn;
	}
}

void
smb_audit_buf_node_destroy(smb_node_t *node)
{
	smb_audit_buf_node_t	*abn;

	abn = node->n_audit_buf;

	if (abn) {
		node->n_audit_buf = NULL;
		kmem_free(abn, sizeof (smb_audit_buf_node_t));
	}
}

/*
 * smb_cred_set_sid
 *
 * Initialize the ksid based on the given smb_id_t.
 */
static void
smb_cred_set_sid(smb_id_t *id, ksid_t *ksid)
{
	char sidstr[SMB_SID_STRSZ];
	int rc;

	ASSERT(id);
	ASSERT(id->i_sidattr.sid);

	ksid->ks_id = id->i_id;
	smb_sid_tostr(id->i_sidattr.sid, sidstr);
	rc = smb_sid_splitstr(sidstr, &ksid->ks_rid);
	ASSERT(rc == 0);

	ksid->ks_attr = id->i_sidattr.attrs;
	ksid->ks_domain = ksid_lookupdomain(sidstr);
}

/*
 * smb_cred_set_sidlist
 *
 * Allocate and initialize the ksidlist based on the Windows group list of the
 * access token.
 */
static ksidlist_t *
smb_cred_set_sidlist(smb_win_grps_t *token_grps)
{
	int i;
	ksidlist_t *lp;

	lp = kmem_zalloc(KSIDLIST_MEM(token_grps->wg_count), KM_SLEEP);
	lp->ksl_ref = 1;
	lp->ksl_nsid = token_grps->wg_count;
	lp->ksl_neid = 0;

	for (i = 0; i < lp->ksl_nsid; i++) {
		smb_cred_set_sid(&token_grps->wg_groups[i],
		    &lp->ksl_sids[i]);
		if (lp->ksl_sids[i].ks_id > IDMAP_WK__MAX_GID)
			lp->ksl_neid++;
	}

	return (lp);
}

/*
 * smb_cred_create
 *
 * The credential of the given SMB user will be allocated and initialized based
 * on the given access token.
 */
cred_t *
smb_cred_create(smb_token_t *token, uint32_t *privileges)
{
	ksid_t			ksid;
	ksidlist_t		*ksidlist = NULL;
	smb_posix_grps_t	*posix_grps;
	cred_t			*cr;

	ASSERT(token);
	ASSERT(token->tkn_posix_grps);
	ASSERT(privileges);

	cr = crget();
	ASSERT(cr != NULL);

	posix_grps = token->tkn_posix_grps;
	if (crsetugid(cr, token->tkn_user->i_id,
	    token->tkn_primary_grp->i_id) != 0) {
		crfree(cr);
		return (NULL);
	}

	if (crsetgroups(cr, posix_grps->pg_ngrps, posix_grps->pg_grps) != 0) {
		crfree(cr);
		return (NULL);
	}

	smb_cred_set_sid(token->tkn_user, &ksid);
	crsetsid(cr, &ksid, KSID_USER);
	smb_cred_set_sid(token->tkn_primary_grp, &ksid);
	crsetsid(cr, &ksid, KSID_GROUP);
	smb_cred_set_sid(token->tkn_owner, &ksid);
	crsetsid(cr, &ksid, KSID_OWNER);
	ksidlist = smb_cred_set_sidlist(token->tkn_win_grps);
	crsetsidlist(cr, ksidlist);

	*privileges = 0;

	if (smb_token_query_privilege(token, SE_BACKUP_LUID)) {
		*privileges |= SMB_USER_PRIV_BACKUP;
	}

	if (smb_token_query_privilege(token, SE_RESTORE_LUID)) {
		*privileges |= SMB_USER_PRIV_RESTORE;
	}

	if (smb_token_query_privilege(token, SE_TAKE_OWNERSHIP_LUID)) {
		*privileges |= SMB_USER_PRIV_TAKE_OWNERSHIP;
		(void) crsetpriv(cr, PRIV_FILE_CHOWN, NULL);
	}

	if (smb_token_query_privilege(token, SE_SECURITY_LUID)) {
		*privileges |= SMB_USER_PRIV_SECURITY;
	}
	return (cr);
}

/*
 * smb_cred_rele
 *
 * The reference count of the user's credential will get decremented if it
 * is non-zero. Otherwise, the credential will be freed.
 */
void
smb_cred_rele(cred_t *cr)
{
	ASSERT(cr);
	crfree(cr);
}

/*
 * smb_cred_is_member
 *
 * Same as smb_token_is_member. The only difference is that
 * we compare the given SID against user SID and the ksidlist
 * of the user's cred.
 */
int
smb_cred_is_member(cred_t *cr, smb_sid_t *sid)
{
	ksidlist_t *ksidlist;
	ksid_t ksid1, *ksid2;
	smb_id_t id;
	int i, rc = 0;

	ASSERT(cr);

	bzero(&id, sizeof (smb_id_t));
	id.i_sidattr.sid = sid;
	smb_cred_set_sid(&id, &ksid1);

	ksidlist = crgetsidlist(cr);
	ASSERT(ksidlist);
	ASSERT(ksid1.ks_domain);
	ASSERT(ksid1.ks_domain->kd_name);

	i = 0;
	ksid2 = crgetsid(cr, KSID_USER);
	do {
		ASSERT(ksid2->ks_domain);
		ASSERT(ksid2->ks_domain->kd_name);

		if (strcmp(ksid1.ks_domain->kd_name,
		    ksid2->ks_domain->kd_name) == 0 &&
		    ksid1.ks_rid == ksid2->ks_rid) {
			rc = 1;
			break;
		}

		ksid2 = &ksidlist->ksl_sids[i];
	} while (i++ < ksidlist->ksl_nsid);

	ksid_rele(&ksid1);
	return (rc);
}

/*
 * smb_kstrdup
 *
 * Duplicate the given string s.
 */
char *
smb_kstrdup(const char *s, size_t n)
{
	char *s2;

	ASSERT(s);
	ASSERT(n);
	s2 = kmem_alloc(n, KM_SLEEP);
	(void) strlcpy(s2, s, n);
	return (s2);
}

/*
 * smb_sync_fsattr
 *
 * Sync file's attributes with file system.
 * The sync takes place based on node->what and node->flags
 * values.
 */
int
smb_sync_fsattr(struct smb_request *sr, cred_t *cr, smb_node_t *node)
{
	uint32_t what;
	int rc = 0;

	if (node->flags & NODE_FLAGS_SET_SIZE) {
		node->flags &= ~NODE_FLAGS_SET_SIZE;
		node->what |= SMB_AT_SIZE;
		node->attr.sa_vattr.va_size = node->n_size;
	}

	if (node->what) {
		/*
		 * This is to prevent another thread from starting
		 * a setattr should this one go to sleep
		 */
		what = node->what;
		node->what = 0;

		node->attr.sa_mask = what;

		rc = smb_fsop_setattr(sr, cr, node, &node->attr, &node->attr);

		if (rc) {
			/* setattr failed, restore the dirty state? */
			node->what = what;
		} else {
			if (what & SMB_AT_ATIME)
				node->flags &= ~NODE_FLAGS_SYNCATIME;
		}
	}

	return (rc);
}

/*
 * smb_cred_create_privs
 *
 * Creates a duplicate credential that contains system privileges for
 * certain SMB privileges: Backup and Restore.
 *
 */
cred_t *
smb_cred_create_privs(cred_t *user_cr, uint32_t privileges)
{
	cred_t *cr = NULL;

	ASSERT(user_cr != NULL);

	if (privileges & (SMB_USER_PRIV_BACKUP | SMB_USER_PRIV_RESTORE))
		cr = crdup(user_cr);

	if (cr == NULL)
		return (NULL);

	if (privileges & SMB_USER_PRIV_BACKUP) {
		(void) crsetpriv(cr, PRIV_FILE_DAC_READ,
		    PRIV_FILE_DAC_SEARCH, PRIV_SYS_MOUNT, NULL);
	}

	if (privileges & SMB_USER_PRIV_RESTORE) {
		(void) crsetpriv(cr, PRIV_FILE_DAC_WRITE,
		    PRIV_FILE_CHOWN, PRIV_FILE_CHOWN_SELF,
		    PRIV_FILE_DAC_SEARCH, PRIV_FILE_LINK_ANY,
		    PRIV_FILE_OWNER, PRIV_FILE_SETID, PRIV_SYS_LINKDIR,
		    PRIV_SYS_MOUNT, NULL);
	}

	return (cr);
}
