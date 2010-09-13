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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <door.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <sys/stat.h>
#include <librcm_impl.h>

#include "librcm_event.h"

#define	dprint	if (debug) (void) printf
static int debug = 1;

#define	BUF_THRESHOLD	1024	/* larger bufs require a free */

/*
 * Lookup seq_num. We can not use the standard nvlist_lookup functions since
 * the nvlist is not allocated with NV_UNIQUE_NAME or NV_UNIQUE_NAME_TYPE.
 */
static int
lookup_seq_num(nvlist_t *nvl, uint64_t *seq_num)
{
	nvpair_t *nvp = NULL;

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		if (strcmp(nvpair_name(nvp), RCM_SEQ_NUM) == 0 &&
		    nvpair_type(nvp) == DATA_TYPE_UINT64)
			return (nvpair_value_uint64(nvp, seq_num));
	}

	return (ENOENT);
}

/*
 * Get event service from a named door.
 *
 * This is similar to sysevent_post_event(), except that it deals with
 * the "return buffer problem":
 *	Typically, the door service places the return buffer on the stack
 *	when calling door_return(). This places an artificial limit on the
 *	size of the return buffer.
 * This problem is solved by placing large buffers on the heap, referenced
 * through door_info. When client detects a large buffer, it will make a
 * second door_call() to free the buffer. The client and the server agrees
 * on a size, which is defined as BUF_THRESHOLD.
 *
 * Returns -1 if message not delivered. With errno set to cause of error.
 * Returns 0 for success with the results returned in posting buffer.
 */
int
get_event_service(char *door_name, void *data, size_t datalen,
    void **result, size_t *rlen)
{
	int service_door, error;
	door_arg_t door_arg;

	/*
	 * Open the service door
	 */
	if ((service_door = open(door_name, O_RDONLY, 0)) == -1) {
		errno = ESRCH;
		return (-1);
	}

retry1:
	door_arg.rbuf = NULL;	/* doorfs will provide return buf */
	door_arg.rsize = 0;
	door_arg.data_ptr = data;
	door_arg.data_size = datalen;
	door_arg.desc_ptr = NULL;
	door_arg.desc_num = 0;

	/*
	 * Make door call
	 * EAGAIN is returned when the door server is temporarily
	 * out of threads to service the door call. So retry.
	 */
	if ((error = door_call(service_door, &door_arg)) == -1 &&
	    errno == EAGAIN) {
		(void) sleep(1);
		goto retry1;
	}

	if ((error == 0) && result) {

		uint64_t seq_num = 0;

		*result = NULL;
		*rlen = 0;
		if (door_arg.rbuf == NULL || door_arg.rsize == 0) {
			dprint("bad return from door call\n");
			(void) close(service_door);
			errno = EFAULT;
			return (-1);
		}

		(void) nvlist_unpack(door_arg.rbuf, door_arg.rsize,
		    (nvlist_t **)result, 0);
		(void) munmap(door_arg.rbuf, door_arg.rsize);

		/*
		 * If requiring a buf free, make another door call.  There is
		 * no need to call munmap() after this door call, though.
		 */
		if (lookup_seq_num((nvlist_t *)*result, &seq_num) == 0) {
retry2:
			door_arg.rbuf = NULL;
			door_arg.rsize = 0;
			door_arg.data_ptr = (char *)&seq_num;
			door_arg.data_size = sizeof (seq_num);
			door_arg.desc_ptr = NULL;
			door_arg.desc_num = 0;
			if (door_call(service_door, &door_arg) == -1) {
				if (errno == EAGAIN) {
					(void) sleep(1);
					goto retry2;
				}
				dprint("fail to free event buf in server\n");
			}
		}
	}

	(void) close(service_door);
	return (error);
}

/*
 * Export an event service door
 */
struct door_result {
	struct door_result *next;
	void *data;
	uint64_t seq_num;
};

typedef struct door_cookie {
	uint64_t	seq_num;
	mutex_t		door_lock;
	void		(*door_func)(void **, size_t *);
	struct door_result *results;
} door_cookie_t;

/*
 * add result to cookie, this is only invoked if result size > BUF_THRESHOLD
 */
static void
add_door_result(door_cookie_t *cook, void *data, uint64_t seq_num)
{
	struct door_result *result;

	/*
	 * Need a better way to handle memory here
	 */
	result = malloc(sizeof (*result));
	while (result == NULL) {
		(void) sleep(1);
		result = malloc(sizeof (*result));
	}
	result->next = NULL;
	result->data = data;
	result->seq_num = seq_num;

	/*
	 * Attach current door result to the door cookie
	 */
	(void) mutex_lock(&cook->door_lock);
	if (cook->results == NULL) {
		cook->results = result;
	} else {
		struct door_result *tmp = cook->results;
		while (tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = result;
	}
	(void) mutex_unlock(&cook->door_lock);
}

/*
 * free a previous door result as described by number.
 */
static void
free_door_result(door_cookie_t *cook, uint64_t num)
{
	struct door_result *prev = NULL, *tmp;

	(void) mutex_lock(&cook->door_lock);
	tmp = cook->results;
	while (tmp && tmp->seq_num != num) {
		prev = tmp;
		tmp = tmp->next;
	}

	if (tmp == NULL) {
		dprint("attempting to free nonexistent buf: %llu\n",
		    (unsigned long long)num);
		(void) mutex_unlock(&cook->door_lock);
		return;
	}

	if (prev) {
		prev->next = tmp->next;
	} else {
		cook->results = tmp->next;
	}
	(void) mutex_unlock(&cook->door_lock);

	free(tmp->data);
	free(tmp);
}

/*ARGSUSED*/
static void
door_service(void *cookie, char *args, size_t alen,
    door_desc_t *ddp, uint_t ndid)
{
	nvlist_t *nvl;
	size_t nvl_size = 0;
	char rbuf[BUF_THRESHOLD];
	door_cookie_t *cook = (door_cookie_t *)cookie;
	uint64_t seq_num = 0;

	/*
	 * Special case for asking to free buffer
	 */
	if (alen == sizeof (uint64_t)) {
		free_door_result(cookie, *(uint64_t *)(void *)args);
		(void) door_return(NULL, 0, NULL, 0);
	}

	/*
	 * door_func update args to point to return results.
	 * memory for results are dynamically allocated.
	 */
	(*cook->door_func)((void **)&args, &alen);

	/*
	 * If no results, just return
	 */
	if (args == NULL) {
		dprint("null results returned from door_func().\n");
		(void) door_return(NULL, 0, NULL, 0);
	}

	/* Determine the size of the packed nvlist */
	nvl = (nvlist_t *)(void *)args;
	args = NULL;
	alen = 0;
	if (errno = nvlist_size(nvl, &nvl_size, NV_ENCODE_NATIVE)) {
		nvlist_free(nvl);
		dprint("failure to sizeup door results: %s\n", strerror(errno));
		(void) door_return(NULL, 0, NULL, 0);
	}

	/*
	 * If the size of the packed nvlist would exceed the buffer threshold
	 * then get a sequence number and add it to the nvlist.
	 */
	if (nvl_size > BUF_THRESHOLD) {
		(void) mutex_lock(&cook->door_lock);
		cook->seq_num++;
		seq_num = cook->seq_num;
		(void) mutex_unlock(&cook->door_lock);
		(void) nvlist_add_uint64(nvl, RCM_SEQ_NUM, seq_num);
	}

	/* Refill the args with a packed version of the nvlist */
	if (errno = nvlist_pack(nvl, &args, &alen, NV_ENCODE_NATIVE, 0)) {
		nvlist_free(nvl);
		dprint("failure to pack door results: %s\n", strerror(errno));
		(void) door_return(NULL, 0, NULL, 0);
	}
	nvlist_free(nvl);

	/*
	 * Based on the size of the packed nvlist, either use the local buffer
	 * or add it to the results list.
	 */
	if (alen <= BUF_THRESHOLD) {
		bcopy(args, rbuf, alen);
		(void) free(args);
		args = rbuf;
	} else {
		/*
		 * for long data, append results to end of queue in cook
		 * and set ndid, ask client to do another door_call
		 * to free the buffer.
		 */
		add_door_result(cook, args, seq_num);
	}

	(void) door_return(args, alen, NULL, 0);
}

int
create_event_service(char *door_name,
    void (*func)(void **data, size_t *datalen))
{
	int service_door, fd;
	door_cookie_t *cookie;

	/* create an fs file */
	fd = open(door_name, O_EXCL|O_CREAT, S_IREAD|S_IWRITE);
	if ((fd == -1) && (errno != EEXIST)) {
		return (-1);
	}
	(void) close(fd);

	/* allocate space for door cookie */
	if ((cookie = calloc(1, sizeof (*cookie))) == NULL) {
		return (-1);
	}

	cookie->door_func = func;
	if ((service_door = door_create(door_service, (void *)cookie,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		dprint("door create failed: %s\n", strerror(errno));
		free(cookie);
		return (-1);
	}

retry:
	(void) fdetach(door_name);
	if (fattach(service_door, door_name) != 0) {
		if (errno == EBUSY) {
			/*
			 * EBUSY error may occur if anyone references the door
			 * file while we are fattach'ing. Since librcm, in the
			 * the process context of a DR initiator program, may
			 * reference the door file (via open/close/stat/
			 * door_call etc.) while we are still fattach'ing,
			 * retry on EBUSY.
			 */
			goto retry;
		}
		dprint("door attaching failed: %s\n", strerror(errno));
		free(cookie);
		(void) close(service_door);
		return (-1);
	}

	return (service_door);
}

int
revoke_event_service(int fd)
{
	struct door_info info;
	door_cookie_t *cookie;

	if (door_info(fd, &info) == -1) {
		return (-1);
	}

	if (door_revoke(fd) != 0) {
		return (-1);
	}

	/* wait for existing door calls to finish */
	(void) sleep(1);

	if ((cookie = (door_cookie_t *)(uintptr_t)info.di_data) != NULL) {
		struct door_result *tmp = cookie->results;
		while (tmp) {
			cookie->results = tmp->next;
			free(tmp->data);
			free(tmp);
			tmp = cookie->results;
		}
		free(cookie);
	}
	return (0);
}
