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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma	weak _putenv = putenv

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <atomic.h>

#define	MIN_ENV_SIZE		128

extern const char		**_environ;
extern void			clean_env();

/*
 * For performance and consistency reasons we expand the _environ list using
 * the trusted "power of two, drop it on the floor" method. This allows for
 * a lockless, single pass implementation of getenv(), yet the memory leak
 * is bounded - in normal circumstances total wastage is never greater than
 * 3x the space needed to hold any _environ list.
 *
 * The only abnormal circumstance is if an application modifies the _environ
 * list pointer directly. Such an application does not conform to POSIX.1
 * 2001. However, we also care about standards which did not foresee this
 * issue. For this reason we keep a working copy of our notion of _environ in
 * my_environ. If, when we are called upon to modify _environ, we ever detect
 * a mismatch between _environ and my_environ we discard all our assumptions
 * concerning the location and size of the _environ list. As an additional
 * precaution we only ever update _environ once we have finished manipulating
 * our working copy.
 *
 * The setenv() API is inherently leaky but we are completely at the mercy
 * of the application.
 *
 * To pacify leak detectors we chain all allocations which are at risk of
 * being leaked in either of the above two scenarios. chunk_list must only
 * be updated under the protection of update_lock.
 *
 * Although we don't allocate the original _environ list it is likely that
 * we will leak this too. Accordingly, we create a reference in initenv().
 * However, we can't be held responsible for such leaks in abnormal (see
 * above) circumstances.
 */

typedef struct chunk {
	struct chunk		*next;
} chunk_t;

static mutex_t			update_lock = DEFAULTMUTEX;
static const char		**orig_environ = NULL;
static const char		**my_environ = NULL;
static const char		**environ_base = NULL;
static int			environ_size = 0;
static int			environ_gen = 0;
static int			initenv_done = 0;
static chunk_t			*chunk_list = NULL;

/*
 * Compute the size an _environ list including the terminating NULL entry.
 * This is the only way we have to determine the size of an _environ list
 * we didn't allocate.
 */
static int
envsize(const char **e)
{
	int			size;

	if (e == NULL)
		return (0);

	for (size = 1; *e != NULL; e++)
		size++;

	return (size);
}

/*
 * Initialization for the following scenarios:
 * 1. The very first time we reference the _environ list we must call in the
 *    NLSPATH janitor, make a reference to the original _environ list to keep
 *    leak detectors happy, initialize my_environ and environ_base, and then
 *    compute environ_size.
 * 2. Whenever we detect that someone else has hijacked _environ (something
 *    very abnormal) we need to reinitialize my_environ and environ_base,
 *    and then recompute environ_size.
 *
 * The local globals my_environ, environ_base and environ_size may be used
 * by others only if initenv_done is true and only under the protection of
 * update_lock. However, our callers, who must NOT be holding update_lock,
 * may safely test initenv_done or my_environ against _environ just prior to
 * calling us because we test these again whilst holding update_lock.
 */
static void
initenv()
{
	if ((my_environ != _environ) || !initenv_done) {
		lmutex_lock(&update_lock);
		if ((my_environ != _environ) || !initenv_done) {
			if (!initenv_done) {
				/* Call the NLSPATH janitor in. */
				clean_env();

				/* Pacify leak detectors in normal operation. */
				orig_environ = _environ;
#ifdef __lint
				my_environ = orig_environ;
#endif
			}

			my_environ = _environ;
			environ_base = my_environ;
			environ_size = envsize(environ_base);
			membar_producer();
			initenv_done = 1;
		}
		lmutex_unlock(&update_lock);
	}
	membar_consumer();
}

/*
 * Search an _environ list for a particular entry. If name_only is set, then
 * string must be the entry name only, and we return the value of the first
 * match. Otherwise, string must be of the form "name=value", and we return
 * the address of the first matching entry.
 */
static const char **
findenv(const char **e, const char *string, int name_only, char **value)
{
	char			target;
	const char		*s1;
	const char		*s2;

	*value = NULL;

	if (e == NULL)
		return (NULL);

	target = name_only ? '\0' : '=';

	for (; (s2 = *e) != NULL; e++) {
		s1 =  string;

		/* Fast comparison for first char. */
		if (*s1 != *s2)
			continue;

		/* Slow comparison for rest of string. */
		while (*s1 == *s2 && *s2 != '=') {
			s1++;
			s2++;
		}

		if (*s1 == target && *s2 == '=') {
			*value = (char *)s2 + 1;
			return (e);
		}
	}
	return (NULL);
}

/*
 * Common code for putenv() and setenv(). We support the lockless getenv()
 * by inserting new entries at the bottom of the list, and by growing the
 * list using the trusted "power of two, drop it on the floor" method. We
 * use a lock (update_lock) to protect all updates to the _environ list, but
 * we are obliged to release this lock whenever we call malloc() or free().
 * A generation number (environ_gen) is bumped whenever names are added to,
 * or removed from, the _environ list so that we can detect collisions with
 * other updaters.
 *
 * Return values
 *   0 : success
 *  -1 : with errno set
 *  -2 : an entry already existed and overwrite was zero
 */
static int
addtoenv(char *string, int overwrite)
{
	char			*value;
	const char		**p;
	chunk_t			*new_chunk;
	const char		**new_environ;
	const char		**new_base;
	int			new_size;
	int			old_gen;

	initenv();

	lmutex_lock(&update_lock);

	for (;;) {
		/*
		 * If the name already exists just overwrite the existing
		 * entry -- except when we were called by setenv() without
		 * the overwrite flag.
		 */
		if ((p = findenv(my_environ, string, 0, &value)) != NULL) {
			if (overwrite) {
				/*
				 * Replace the value in situ. No name was
				 * added, so there is no need to bump the
				 * generation number.
				 */
				*p = string;
				lmutex_unlock(&update_lock);
				return (0);
			} else {
				/* No change. */
				lmutex_unlock(&update_lock);
				return (-2);
			}
		}

		/* Try to insert the new entry at the bottom of the list. */
		if (environ_base < my_environ) {
			/*
			 * The new value must be visible before we decrement
			 * the _environ list pointer.
			 */
			my_environ[-1] = string;
			membar_producer();
			my_environ--;
			_environ = my_environ;

			/*
			 * We've added a name, so bump the generation number.
			 */
			environ_gen++;

			lmutex_unlock(&update_lock);
			return (0);
		}

		/*
		 * There is no room. Attempt to allocate a new _environ list
		 * which is at least double the size of the current one. See
		 * comment above concerning locking and malloc() etc.
		 */
		new_size = environ_size * 2;
		if (new_size < MIN_ENV_SIZE)
			new_size = MIN_ENV_SIZE;

		old_gen = environ_gen;
		lmutex_unlock(&update_lock);

		new_chunk = malloc(sizeof (chunk_t) +
		    new_size * sizeof (char *));
		if (new_chunk == NULL) {
			errno = ENOMEM;
			return (-1);
		}

		lmutex_lock(&update_lock);

		/*
		 * If no other thread added or removed names while the lock
		 * was dropped, it is time to break out of this loop.
		 */
		if (environ_gen == old_gen)
			break;

		/*
		 * At least one name has been added or removed, so we need to
		 * try again. It is very likely that we will find sufficient
		 * space the next time around.
		 */
		lmutex_unlock(&update_lock);
		free(new_chunk);
		lmutex_lock(&update_lock);
	}

	/* Add the new chunk to chunk_list to hide potential future leak. */
	new_chunk->next = chunk_list;
	chunk_list = new_chunk;

	/* Copy the old _environ list into the top of the new _environ list. */
	new_base = (const char **)(new_chunk + 1);
	new_environ = &new_base[(new_size - 1) - environ_size];
	(void) memcpy(new_environ, my_environ, environ_size * sizeof (char *));

	/* Insert the new entry at the bottom of the new _environ list. */
	new_environ[-1] = string;
	new_environ--;

	/* Ensure that the new _environ list is visible to all. */
	membar_producer();

	/* Make the switch (dropping the old _environ list on the floor). */
	environ_base = new_base;
	my_environ = new_environ;
	_environ = my_environ;
	environ_size = new_size;

	/* We've added a name, so bump the generation number. */
	environ_gen++;

	lmutex_unlock(&update_lock);
	return (0);
}

/*
 * All the work for putenv() is done in addtoenv().
 */
int
putenv(char *string)
{
	/*
	 * Historically a call to putenv() with no '=' in the string would work
	 * great until someone called getenv() on that particular environment
	 * variable again. As we've always treated this as valid, rather than
	 * teaching the rest of the environment code how to handle something
	 * without an '=' sign, it instead just calls unsetenv().
	 */
	if (strchr(string, '=') == NULL)
		return (unsetenv(string));

	return (addtoenv(string, 1));
}

/*
 * setenv() is a little more complex than putenv() because we have to allocate
 * and construct an _environ entry on behalf of the caller. The bulk of the
 * work is still done in addtoenv().
 */

int
setenv(const char *envname, const char *envval, int overwrite)
{
	chunk_t			*new_chunk;
	char			*new_string;
	size_t			name_len;
	size_t			val_len;
	int			res;

	if (envname == NULL || *envname == 0 || strchr(envname, '=') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	name_len = strlen(envname);
	val_len = strlen(envval);

	new_chunk = malloc(sizeof (chunk_t) + name_len + val_len + 2);
	if (new_chunk == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	new_string = (char *)(new_chunk + 1);

	(void) memcpy(new_string, envname, name_len);
	new_string[name_len] = '=';
	(void) memcpy(new_string + name_len + 1, envval, val_len);
	new_string[name_len + 1 + val_len] = 0;

	if ((res = addtoenv(new_string, overwrite)) < 0) {
		free(new_chunk);
		if (res == -2) {
			/* The name already existed, but not an error. */
			return (0);
		} else {
			/* i.e. res == -1 which means only one thing. */
			errno = ENOMEM;
			return (-1);
		}
	}

	/* Hide potential leak of new_string. */
	lmutex_lock(&update_lock);
	new_chunk->next = chunk_list;
	chunk_list = new_chunk;
	lmutex_unlock(&update_lock);

	return (0);
}

/*
 * unsetenv() is tricky because we need to compress the _environ list in a way
 * which supports a lockless getenv(). The approach here is to move the first
 * entry from the enrivon list into the space occupied by the entry to be
 * deleted, and then to increment _environ. This has the added advantage of
 * making _any_ incremental linear search of the _environ list consistent (i.e.
 * we will not break any naughty apps which read the list without our help).
 */
int
unsetenv(const char *name)
{
	const char		**p;
	char			*value;

	if (name == NULL || *name == 0 || strchr(name, '=') != NULL) {
		errno = EINVAL;
		return (-1);
	}

	initenv();

	lmutex_lock(&update_lock);

	/*
	 * Find the target, overwrite it with the first entry, increment the
	 * _environ pointer.
	 */
	if ((p = findenv(my_environ, name, 1, &value)) != NULL) {
		/* Overwrite target with the first entry. */
		*p = my_environ[0];

		/* Ensure that the moved entry is visible to all.  */
		membar_producer();

		/* Shrink the _environ list. */
		my_environ++;
		_environ = my_environ;

		/* Make sure addtoenv() knows that we've removed a name. */
		environ_gen++;
	}

	lmutex_unlock(&update_lock);
	return (0);
}

/*
 * Dump entire environment.
 */
int
clearenv(void)
{
	/*
	 * Just drop the entire environment list on the floor, as it
	 * would be non-trivial to try and free the used memory.
	 */
	static const char *nullp = NULL;

	lmutex_lock(&update_lock);
	_environ = &nullp;
	my_environ = NULL;
	environ_base = NULL;
	environ_size = 0;
	environ_gen++;
	membar_producer();
	lmutex_unlock(&update_lock);

	return (0);
}

/*
 * At last, a lockless implementation of getenv()!
 */
char *
getenv(const char *name)
{
	char			*value;

	initenv();

	if (findenv(_environ, name, 1, &value) != NULL)
		return (value);

	return (NULL);
}
