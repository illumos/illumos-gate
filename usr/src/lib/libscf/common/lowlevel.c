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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 * Copyright 2016 RackTop Systems.
 */

/*
 * This is the main implementation file for the low-level repository
 * interface.
 */

#include "lowlevel_impl.h"

#include "repcache_protocol.h"
#include "scf_type.h"

#include <assert.h>
#include <alloca.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libuutil.h>
#include <poll.h>
#include <pthread.h>
#include <synch.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <libzonecfg.h>
#include <unistd.h>
#include <dlfcn.h>

#define	ENV_SCF_DEBUG		"LIBSCF_DEBUG"
#define	ENV_SCF_DOORPATH	"LIBSCF_DOORPATH"

static uint32_t default_debug = 0;
static const char *default_door_path = REPOSITORY_DOOR_NAME;

#define	CALL_FAILED		-1
#define	RESULT_TOO_BIG		-2
#define	NOT_BOUND		-3

static pthread_mutex_t	lowlevel_init_lock;
static int32_t		lowlevel_inited;

static uu_list_pool_t	*tran_entry_pool;
static uu_list_pool_t	*datael_pool;
static uu_list_pool_t	*iter_pool;

/*
 * base32[] index32[] are used in base32 encoding and decoding.
 */
static char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static char index32[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 0-7 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 8-15 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 16-23 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 24-31 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 32-39 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 40-47 */
	-1, -1, 26, 27, 28, 29, 30, 31,	/* 48-55 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 56-63 */
	-1, 0, 1, 2, 3, 4, 5, 6,	/* 64-71 */
	7, 8, 9, 10, 11, 12, 13, 14,	/* 72-79 */
	15, 16, 17, 18, 19, 20, 21, 22,	/* 80-87 */
	23, 24, 25, -1, -1, -1, -1, -1,	/* 88-95 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 96-103 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 104-111 */
	-1, -1, -1, -1, -1, -1, -1, -1,	/* 112-119 */
	-1, -1, -1, -1, -1, -1, -1, -1	/* 120-127 */
};

#define	DECODE32_GS	(8)	/* scf_decode32 group size */

#ifdef lint
#define	assert_nolint(x) (void)0
#else
#define	assert_nolint(x) assert(x)
#endif

static void scf_iter_reset_locked(scf_iter_t *iter);
static void scf_value_reset_locked(scf_value_t *val, int and_destroy);

#define	TYPE_VALUE	(-100)

/*
 * Hold and release subhandles.  We only allow one thread access to the
 * subhandles at a time, and he can use any subset, grabbing and releasing
 * them in any order.  The only restrictions are that you cannot hold an
 * already-held subhandle, and all subhandles must be released before
 * returning to the original caller.
 */
static void
handle_hold_subhandles(scf_handle_t *h, int mask)
{
	assert(mask != 0 && (mask & ~RH_HOLD_ALL) == 0);

	(void) pthread_mutex_lock(&h->rh_lock);
	while (h->rh_hold_flags != 0 && h->rh_holder != pthread_self()) {
		int cancel_state;

		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
		    &cancel_state);
		(void) pthread_cond_wait(&h->rh_cv, &h->rh_lock);
		(void) pthread_setcancelstate(cancel_state, NULL);
	}
	if (h->rh_hold_flags == 0)
		h->rh_holder = pthread_self();
	assert(!(h->rh_hold_flags & mask));
	h->rh_hold_flags |= mask;
	(void) pthread_mutex_unlock(&h->rh_lock);
}

static void
handle_rele_subhandles(scf_handle_t *h, int mask)
{
	assert(mask != 0 && (mask & ~RH_HOLD_ALL) == 0);

	(void) pthread_mutex_lock(&h->rh_lock);
	assert(h->rh_holder == pthread_self());
	assert((h->rh_hold_flags & mask));

	h->rh_hold_flags &= ~mask;
	if (h->rh_hold_flags == 0)
		(void) pthread_cond_signal(&h->rh_cv);
	(void) pthread_mutex_unlock(&h->rh_lock);
}

#define	HOLD_HANDLE(h, flag, field) \
	(handle_hold_subhandles((h), (flag)), (h)->field)

#define	RELE_HANDLE(h, flag) \
	(handle_rele_subhandles((h), (flag)))

/*
 * convenience macros, for functions that only need a one or two handles at
 * any given time
 */
#define	HANDLE_HOLD_ITER(h)	HOLD_HANDLE((h), RH_HOLD_ITER, rh_iter)
#define	HANDLE_HOLD_SCOPE(h)	HOLD_HANDLE((h), RH_HOLD_SCOPE, rh_scope)
#define	HANDLE_HOLD_SERVICE(h)	HOLD_HANDLE((h), RH_HOLD_SERVICE, rh_service)
#define	HANDLE_HOLD_INSTANCE(h)	HOLD_HANDLE((h), RH_HOLD_INSTANCE, rh_instance)
#define	HANDLE_HOLD_SNAPSHOT(h)	HOLD_HANDLE((h), RH_HOLD_SNAPSHOT, rh_snapshot)
#define	HANDLE_HOLD_SNAPLVL(h)	HOLD_HANDLE((h), RH_HOLD_SNAPLVL, rh_snaplvl)
#define	HANDLE_HOLD_PG(h)	HOLD_HANDLE((h), RH_HOLD_PG, rh_pg)
#define	HANDLE_HOLD_PROPERTY(h)	HOLD_HANDLE((h), RH_HOLD_PROPERTY, rh_property)
#define	HANDLE_HOLD_VALUE(h)	HOLD_HANDLE((h), RH_HOLD_VALUE, rh_value)

#define	HANDLE_RELE_ITER(h)	RELE_HANDLE((h), RH_HOLD_ITER)
#define	HANDLE_RELE_SCOPE(h)	RELE_HANDLE((h), RH_HOLD_SCOPE)
#define	HANDLE_RELE_SERVICE(h)	RELE_HANDLE((h), RH_HOLD_SERVICE)
#define	HANDLE_RELE_INSTANCE(h)	RELE_HANDLE((h), RH_HOLD_INSTANCE)
#define	HANDLE_RELE_SNAPSHOT(h)	RELE_HANDLE((h), RH_HOLD_SNAPSHOT)
#define	HANDLE_RELE_SNAPLVL(h)	RELE_HANDLE((h), RH_HOLD_SNAPLVL)
#define	HANDLE_RELE_PG(h)	RELE_HANDLE((h), RH_HOLD_PG)
#define	HANDLE_RELE_PROPERTY(h)	RELE_HANDLE((h), RH_HOLD_PROPERTY)
#define	HANDLE_RELE_VALUE(h)	RELE_HANDLE((h), RH_HOLD_VALUE)

/*ARGSUSED*/
static int
transaction_entry_compare(const void *l_arg, const void *r_arg, void *private)
{
	const char *l_prop =
	    ((scf_transaction_entry_t *)l_arg)->entry_property;
	const char *r_prop =
	    ((scf_transaction_entry_t *)r_arg)->entry_property;

	int ret;

	ret = strcmp(l_prop, r_prop);
	if (ret > 0)
		return (1);
	if (ret < 0)
		return (-1);
	return (0);
}

static int
datael_compare(const void *l_arg, const void *r_arg, void *private)
{
	uint32_t l_id = ((scf_datael_t *)l_arg)->rd_entity;
	uint32_t r_id = (r_arg != NULL) ? ((scf_datael_t *)r_arg)->rd_entity :
	    *(uint32_t *)private;

	if (l_id > r_id)
		return (1);
	if (l_id < r_id)
		return (-1);
	return (0);
}

static int
iter_compare(const void *l_arg, const void *r_arg, void *private)
{
	uint32_t l_id = ((scf_iter_t *)l_arg)->iter_id;
	uint32_t r_id = (r_arg != NULL) ? ((scf_iter_t *)r_arg)->iter_id :
	    *(uint32_t *)private;

	if (l_id > r_id)
		return (1);
	if (l_id < r_id)
		return (-1);
	return (0);
}

static int
lowlevel_init(void)
{
	const char *debug;
	const char *door_path;

	(void) pthread_mutex_lock(&lowlevel_init_lock);
	if (lowlevel_inited == 0) {
		if (!issetugid() &&
		    (debug = getenv(ENV_SCF_DEBUG)) != NULL && debug[0] != 0 &&
		    uu_strtoint(debug, &default_debug, sizeof (default_debug),
		    0, 0, 0) == -1) {
			(void) fprintf(stderr, "LIBSCF: $%s (%s): %s",
			    ENV_SCF_DEBUG, debug,
			    uu_strerror(uu_error()));
		}

		if (!issetugid() &&
		    (door_path = getenv(ENV_SCF_DOORPATH)) != NULL &&
		    door_path[0] != 0) {
			default_door_path = strdup(door_path);
			if (default_door_path == NULL)
				default_door_path = door_path;
		}

		datael_pool = uu_list_pool_create("SUNW,libscf_datael",
		    sizeof (scf_datael_t), offsetof(scf_datael_t, rd_node),
		    datael_compare, UU_LIST_POOL_DEBUG);

		iter_pool = uu_list_pool_create("SUNW,libscf_iter",
		    sizeof (scf_iter_t), offsetof(scf_iter_t, iter_node),
		    iter_compare, UU_LIST_POOL_DEBUG);

		assert_nolint(offsetof(scf_transaction_entry_t,
		    entry_property) == 0);
		tran_entry_pool = uu_list_pool_create(
		    "SUNW,libscf_transaction_entity",
		    sizeof (scf_transaction_entry_t),
		    offsetof(scf_transaction_entry_t, entry_link),
		    transaction_entry_compare, UU_LIST_POOL_DEBUG);

		if (datael_pool == NULL || iter_pool == NULL ||
		    tran_entry_pool == NULL) {
			lowlevel_inited = -1;
			goto end;
		}

		if (!scf_setup_error()) {
			lowlevel_inited = -1;
			goto end;
		}
		lowlevel_inited = 1;
	}
end:
	(void) pthread_mutex_unlock(&lowlevel_init_lock);
	if (lowlevel_inited > 0)
		return (1);
	return (0);
}

static const struct {
	scf_type_t ti_type;
	rep_protocol_value_type_t ti_proto_type;
	const char *ti_name;
} scf_type_info[] = {
	{SCF_TYPE_BOOLEAN,	REP_PROTOCOL_TYPE_BOOLEAN,
	    SCF_TYPE_STRING_BOOLEAN},
	{SCF_TYPE_COUNT,	REP_PROTOCOL_TYPE_COUNT,
	    SCF_TYPE_STRING_COUNT},
	{SCF_TYPE_INTEGER,	REP_PROTOCOL_TYPE_INTEGER,
	    SCF_TYPE_STRING_INTEGER},
	{SCF_TYPE_TIME,		REP_PROTOCOL_TYPE_TIME,
	    SCF_TYPE_STRING_TIME},
	{SCF_TYPE_ASTRING,	REP_PROTOCOL_TYPE_STRING,
	    SCF_TYPE_STRING_ASTRING},
	{SCF_TYPE_OPAQUE,	REP_PROTOCOL_TYPE_OPAQUE,
	    SCF_TYPE_STRING_OPAQUE},
	{SCF_TYPE_USTRING,	REP_PROTOCOL_SUBTYPE_USTRING,
	    SCF_TYPE_STRING_USTRING},
	{SCF_TYPE_URI,		REP_PROTOCOL_SUBTYPE_URI,
	    SCF_TYPE_STRING_URI},
	{SCF_TYPE_FMRI,		REP_PROTOCOL_SUBTYPE_FMRI,
	    SCF_TYPE_STRING_FMRI},
	{SCF_TYPE_HOST,		REP_PROTOCOL_SUBTYPE_HOST,
	    SCF_TYPE_STRING_HOST},
	{SCF_TYPE_HOSTNAME,	REP_PROTOCOL_SUBTYPE_HOSTNAME,
	    SCF_TYPE_STRING_HOSTNAME},
	{SCF_TYPE_NET_ADDR,	REP_PROTOCOL_SUBTYPE_NETADDR,
	    SCF_TYPE_STRING_NET_ADDR},
	{SCF_TYPE_NET_ADDR_V4,	REP_PROTOCOL_SUBTYPE_NETADDR_V4,
	    SCF_TYPE_STRING_NET_ADDR_V4},
	{SCF_TYPE_NET_ADDR_V6,	REP_PROTOCOL_SUBTYPE_NETADDR_V6,
	    SCF_TYPE_STRING_NET_ADDR_V6}
};

#define	SCF_TYPE_INFO_COUNT (sizeof (scf_type_info) / sizeof (*scf_type_info))
static rep_protocol_value_type_t
scf_type_to_protocol_type(scf_type_t t)
{
	int i;

	for (i = 0; i < SCF_TYPE_INFO_COUNT; i++)
		if (scf_type_info[i].ti_type == t)
			return (scf_type_info[i].ti_proto_type);

	return (REP_PROTOCOL_TYPE_INVALID);
}

static scf_type_t
scf_protocol_type_to_type(rep_protocol_value_type_t t)
{
	int i;

	for (i = 0; i < SCF_TYPE_INFO_COUNT; i++)
		if (scf_type_info[i].ti_proto_type == t)
			return (scf_type_info[i].ti_type);

	return (SCF_TYPE_INVALID);
}

const char *
scf_type_to_string(scf_type_t ty)
{
	int i;

	for (i = 0; i < SCF_TYPE_INFO_COUNT; i++)
		if (scf_type_info[i].ti_type == ty)
			return (scf_type_info[i].ti_name);

	return ("unknown");
}

scf_type_t
scf_string_to_type(const char *name)
{
	int i;

	for (i = 0; i < sizeof (scf_type_info) / sizeof (*scf_type_info); i++)
		if (strcmp(scf_type_info[i].ti_name, name) == 0)
			return (scf_type_info[i].ti_type);

	return (SCF_TYPE_INVALID);
}

int
scf_type_base_type(scf_type_t type, scf_type_t *out)
{
	rep_protocol_value_type_t t = scf_type_to_protocol_type(type);
	if (t == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	*out = scf_protocol_type_to_type(scf_proto_underlying_type(t));
	return (SCF_SUCCESS);
}

/*
 * Convert a protocol error code into an SCF_ERROR_* code.
 */
static scf_error_t
proto_error(rep_protocol_responseid_t e)
{
	switch (e) {
	case REP_PROTOCOL_FAIL_MISORDERED:
	case REP_PROTOCOL_FAIL_UNKNOWN_ID:
	case REP_PROTOCOL_FAIL_INVALID_TYPE:
	case REP_PROTOCOL_FAIL_TRUNCATED:
	case REP_PROTOCOL_FAIL_TYPE_MISMATCH:
	case REP_PROTOCOL_FAIL_NOT_APPLICABLE:
	case REP_PROTOCOL_FAIL_UNKNOWN:
		return (SCF_ERROR_INTERNAL);

	case REP_PROTOCOL_FAIL_BAD_TX:
		return (SCF_ERROR_INVALID_ARGUMENT);
	case REP_PROTOCOL_FAIL_BAD_REQUEST:
		return (SCF_ERROR_INVALID_ARGUMENT);
	case REP_PROTOCOL_FAIL_NO_RESOURCES:
		return (SCF_ERROR_NO_RESOURCES);
	case REP_PROTOCOL_FAIL_NOT_FOUND:
		return (SCF_ERROR_NOT_FOUND);
	case REP_PROTOCOL_FAIL_DELETED:
		return (SCF_ERROR_DELETED);
	case REP_PROTOCOL_FAIL_NOT_SET:
		return (SCF_ERROR_NOT_SET);
	case REP_PROTOCOL_FAIL_EXISTS:
		return (SCF_ERROR_EXISTS);
	case REP_PROTOCOL_FAIL_DUPLICATE_ID:
		return (SCF_ERROR_EXISTS);
	case REP_PROTOCOL_FAIL_PERMISSION_DENIED:
		return (SCF_ERROR_PERMISSION_DENIED);
	case REP_PROTOCOL_FAIL_BACKEND_ACCESS:
		return (SCF_ERROR_BACKEND_ACCESS);
	case REP_PROTOCOL_FAIL_BACKEND_READONLY:
		return (SCF_ERROR_BACKEND_READONLY);

	case REP_PROTOCOL_SUCCESS:
	case REP_PROTOCOL_DONE:
	case REP_PROTOCOL_FAIL_NOT_LATEST:	/* TX code should handle this */
	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Bad error code %d passed to proto_error().\n",
		    __FILE__, __LINE__, e);
#endif
		abort();
		/*NOTREACHED*/
	}
}

ssize_t
scf_limit(uint32_t limit)
{
	switch (limit) {
	case SCF_LIMIT_MAX_NAME_LENGTH:
	case SCF_LIMIT_MAX_PG_TYPE_LENGTH:
		return (REP_PROTOCOL_NAME_LEN - 1);
	case SCF_LIMIT_MAX_VALUE_LENGTH:
		return (REP_PROTOCOL_VALUE_LEN - 1);
	case SCF_LIMIT_MAX_FMRI_LENGTH:
		return (SCF_FMRI_PREFIX_MAX_LEN +
		    sizeof (SCF_FMRI_SCOPE_PREFIX) - 1 +
		    sizeof (SCF_FMRI_SCOPE_SUFFIX) - 1 +
		    sizeof (SCF_FMRI_SERVICE_PREFIX) - 1 +
		    sizeof (SCF_FMRI_INSTANCE_PREFIX) - 1 +
		    sizeof (SCF_FMRI_PROPERTYGRP_PREFIX) - 1 +
		    sizeof (SCF_FMRI_PROPERTY_PREFIX) - 1 +
		    5 * (REP_PROTOCOL_NAME_LEN - 1));
	default:
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
}

static size_t
scf_opaque_decode(char *out_arg, const char *in, size_t max_out)
{
	char a, b;
	char *out = out_arg;

	while (max_out > 0 && (a = in[0]) != 0 && (b = in[1]) != 0) {
		in += 2;

		if (a >= '0' && a <= '9')
			a -= '0';
		else if (a >= 'a' && a <= 'f')
			a = a - 'a' + 10;
		else if (a >= 'A' && a <= 'F')
			a = a - 'A' + 10;
		else
			break;

		if (b >= '0' && b <= '9')
			b -= '0';
		else if (b >= 'a' && b <= 'f')
			b = b - 'a' + 10;
		else if (b >= 'A' && b <= 'F')
			b = b - 'A' + 10;
		else
			break;

		*out++ = (a << 4) | b;
		max_out--;
	}

	return (out - out_arg);
}

static size_t
scf_opaque_encode(char *out_arg, const char *in_arg, size_t in_sz)
{
	uint8_t *in = (uint8_t *)in_arg;
	uint8_t *end = in + in_sz;
	char *out = out_arg;

	if (out == NULL)
		return (2 * in_sz);

	while (in < end) {
		uint8_t c = *in++;

		uint8_t a = (c & 0xf0) >> 4;
		uint8_t b = (c & 0x0f);

		if (a <= 9)
			*out++ = a + '0';
		else
			*out++ = a + 'a' - 10;

		if (b <= 9)
			*out++ = b + '0';
		else
			*out++ = b + 'a' - 10;
	}

	*out = 0;

	return (out - out_arg);
}

static void
handle_do_close(scf_handle_t *h)
{
	assert(MUTEX_HELD(&h->rh_lock));
	assert(h->rh_doorfd != -1);

	/*
	 * if there are any active FD users, we just move the FD over
	 * to rh_doorfd_old -- they'll close it when they finish.
	 */
	if (h->rh_fd_users > 0) {
		h->rh_doorfd_old = h->rh_doorfd;
		h->rh_doorfd = -1;
	} else {
		assert(h->rh_doorfd_old == -1);
		(void) close(h->rh_doorfd);
		h->rh_doorfd = -1;
	}
}

/*
 * Check if a handle is currently bound.  fork()ing implicitly unbinds
 * the handle in the child.
 */
static int
handle_is_bound(scf_handle_t *h)
{
	assert(MUTEX_HELD(&h->rh_lock));

	if (h->rh_doorfd == -1)
		return (0);

	if (getpid() == h->rh_doorpid)
		return (1);

	/* forked since our last bind -- initiate handle close */
	handle_do_close(h);
	return (0);
}

static int
handle_has_server_locked(scf_handle_t *h)
{
	door_info_t i;
	assert(MUTEX_HELD(&h->rh_lock));

	return (handle_is_bound(h) && door_info(h->rh_doorfd, &i) != -1 &&
	    i.di_target != -1);
}

static int
handle_has_server(scf_handle_t *h)
{
	int ret;

	(void) pthread_mutex_lock(&h->rh_lock);
	ret = handle_has_server_locked(h);
	(void) pthread_mutex_unlock(&h->rh_lock);

	return (ret);
}

/*
 * This makes a door request on the client door associated with handle h.
 * It will automatically retry calls which fail on EINTR.  If h is not bound,
 * returns NOT_BOUND.  If the door call fails or the server response is too
 * small, returns CALL_FAILED.  If the server response is too big, truncates the
 * response and returns RESULT_TOO_BIG.  Otherwise, the size of the result is
 * returned.
 */
static ssize_t
make_door_call(scf_handle_t *h, const void *req, size_t req_sz,
    void *res, size_t res_sz)
{
	door_arg_t arg;
	int r;

	assert(MUTEX_HELD(&h->rh_lock));

	if (!handle_is_bound(h)) {
		return (NOT_BOUND);
	}

	arg.data_ptr = (void *)req;
	arg.data_size = req_sz;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = res;
	arg.rsize = res_sz;

	while ((r = door_call(h->rh_doorfd, &arg)) < 0) {
		if (errno != EINTR)
			break;
	}

	if (r < 0) {
		return (CALL_FAILED);
	}

	if (arg.desc_num > 0) {
		while (arg.desc_num > 0) {
			if (arg.desc_ptr->d_attributes & DOOR_DESCRIPTOR) {
				int cfd = arg.desc_ptr->d_data.d_desc.d_id;
				(void) close(cfd);
			}
			arg.desc_ptr++;
			arg.desc_num--;
		}
	}
	if (arg.data_ptr != res && arg.data_size > 0)
		(void) memmove(res, arg.data_ptr, MIN(arg.data_size, res_sz));

	if (arg.rbuf != res)
		(void) munmap(arg.rbuf, arg.rsize);

	if (arg.data_size > res_sz)
		return (RESULT_TOO_BIG);

	if (arg.data_size < sizeof (uint32_t))
		return (CALL_FAILED);

	return (arg.data_size);
}

/*
 * Should only be used when r < 0.
 */
#define	DOOR_ERRORS_BLOCK(r)	{					\
	switch (r) {							\
	case NOT_BOUND:							\
		return (scf_set_error(SCF_ERROR_NOT_BOUND));		\
									\
	case CALL_FAILED:						\
		return (scf_set_error(SCF_ERROR_CONNECTION_BROKEN));	\
									\
	case RESULT_TOO_BIG:						\
		return (scf_set_error(SCF_ERROR_INTERNAL));		\
									\
	default:							\
		assert(r == NOT_BOUND || r == CALL_FAILED ||		\
		    r == RESULT_TOO_BIG);				\
		abort();						\
	}								\
}

/*
 * Like make_door_call(), but takes an fd instead of a handle, and expects
 * a single file descriptor, returned via res_fd.
 *
 * If no file descriptor is returned, *res_fd == -1.
 */
static int
make_door_call_retfd(int fd, const void *req, size_t req_sz, void *res,
    size_t res_sz, int *res_fd)
{
	door_arg_t arg;
	int r;
	char rbuf[256];

	*res_fd = -1;

	if (fd == -1)
		return (NOT_BOUND);

	arg.data_ptr = (void *)req;
	arg.data_size = req_sz;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = rbuf;
	arg.rsize = sizeof (rbuf);

	while ((r = door_call(fd, &arg)) < 0) {
		if (errno != EINTR)
			break;
	}

	if (r < 0)
		return (CALL_FAILED);

	if (arg.desc_num > 1) {
		while (arg.desc_num > 0) {
			if (arg.desc_ptr->d_attributes & DOOR_DESCRIPTOR) {
				int cfd =
				    arg.desc_ptr->d_data.d_desc.d_descriptor;
				(void) close(cfd);
			}
			arg.desc_ptr++;
			arg.desc_num--;
		}
	}
	if (arg.desc_num == 1 && arg.desc_ptr->d_attributes & DOOR_DESCRIPTOR)
		*res_fd = arg.desc_ptr->d_data.d_desc.d_descriptor;

	if (arg.data_size > 0)
		(void) memmove(res, arg.data_ptr, MIN(arg.data_size, res_sz));

	if (arg.rbuf != rbuf)
		(void) munmap(arg.rbuf, arg.rsize);

	if (arg.data_size > res_sz)
		return (RESULT_TOO_BIG);

	if (arg.data_size < sizeof (uint32_t))
		return (CALL_FAILED);

	return (arg.data_size);
}

/*
 * Fails with
 *   _VERSION_MISMATCH
 *   _NO_MEMORY
 */
scf_handle_t *
scf_handle_create(scf_version_t v)
{
	scf_handle_t *ret;
	int failed;

	/*
	 * This will need to be revisited when we bump SCF_VERSION
	 */
	if (v != SCF_VERSION) {
		(void) scf_set_error(SCF_ERROR_VERSION_MISMATCH);
		return (NULL);
	}

	if (!lowlevel_init()) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	ret = uu_zalloc(sizeof (*ret));
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	ret->rh_dataels = uu_list_create(datael_pool, ret, 0);
	ret->rh_iters = uu_list_create(iter_pool, ret, 0);
	if (ret->rh_dataels == NULL || ret->rh_iters == NULL) {
		if (ret->rh_dataels != NULL)
			uu_list_destroy(ret->rh_dataels);
		if (ret->rh_iters != NULL)
			uu_list_destroy(ret->rh_iters);
		uu_free(ret);
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	ret->rh_doorfd = -1;
	ret->rh_doorfd_old = -1;
	(void) pthread_mutex_init(&ret->rh_lock, NULL);

	handle_hold_subhandles(ret, RH_HOLD_ALL);

	failed = ((ret->rh_iter = scf_iter_create(ret)) == NULL ||
	    (ret->rh_scope = scf_scope_create(ret)) == NULL ||
	    (ret->rh_service = scf_service_create(ret)) == NULL ||
	    (ret->rh_instance = scf_instance_create(ret)) == NULL ||
	    (ret->rh_snapshot = scf_snapshot_create(ret)) == NULL ||
	    (ret->rh_snaplvl = scf_snaplevel_create(ret)) == NULL ||
	    (ret->rh_pg = scf_pg_create(ret)) == NULL ||
	    (ret->rh_property = scf_property_create(ret)) == NULL ||
	    (ret->rh_value = scf_value_create(ret)) == NULL);

	/*
	 * these subhandles count as internal references, not external ones.
	 */
	ret->rh_intrefs = ret->rh_extrefs;
	ret->rh_extrefs = 0;
	handle_rele_subhandles(ret, RH_HOLD_ALL);

	if (failed) {
		scf_handle_destroy(ret);
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	scf_value_set_count(ret->rh_value, default_debug);
	(void) scf_handle_decorate(ret, "debug", ret->rh_value);

	return (ret);
}

/*
 * Fails with
 *   _NO_MEMORY
 *   _NO_SERVER - server door could not be open()ed
 *		  door call failed
 *		  door_info() failed
 *   _VERSION_MISMATCH - server returned bad file descriptor
 *			 server claimed bad request
 *			 server reported version mismatch
 *			 server refused with unknown reason
 *   _INVALID_ARGUMENT
 *   _NO_RESOURCES - server is out of memory
 *   _PERMISSION_DENIED
 *   _INTERNAL - could not set up entities or iters
 *		 server response too big
 */
scf_handle_t *
_scf_handle_create_and_bind(scf_version_t ver)
{
	scf_handle_t *h;

	h = scf_handle_create(ver);
	if (h == NULL)
		return (NULL);

	if (scf_handle_bind(h) == -1) {
		scf_handle_destroy(h);
		return (NULL);
	}
	return (h);
}

int
scf_handle_decorate(scf_handle_t *handle, const char *name, scf_value_t *v)
{
	if (v != SCF_DECORATE_CLEAR && handle != v->value_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&handle->rh_lock);
	if (handle_is_bound(handle)) {
		(void) pthread_mutex_unlock(&handle->rh_lock);
		return (scf_set_error(SCF_ERROR_IN_USE));
	}
	(void) pthread_mutex_unlock(&handle->rh_lock);

	if (strcmp(name, "debug") == 0) {
		if (v == SCF_DECORATE_CLEAR) {
			(void) pthread_mutex_lock(&handle->rh_lock);
			handle->rh_debug = 0;
			(void) pthread_mutex_unlock(&handle->rh_lock);
		} else {
			uint64_t val;
			if (scf_value_get_count(v, &val) < 0)
				return (-1);		/* error already set */

			(void) pthread_mutex_lock(&handle->rh_lock);
			handle->rh_debug = (uid_t)val;
			(void) pthread_mutex_unlock(&handle->rh_lock);
		}
		return (0);
	}
	if (strcmp(name, "door_path") == 0) {
		char name[sizeof (handle->rh_doorpath)];

		if (v == SCF_DECORATE_CLEAR) {
			(void) pthread_mutex_lock(&handle->rh_lock);
			handle->rh_doorpath[0] = 0;
			(void) pthread_mutex_unlock(&handle->rh_lock);
		} else {
			ssize_t len;

			if ((len = scf_value_get_astring(v, name,
			    sizeof (name))) < 0) {
				return (-1);		/* error already set */
			}
			if (len == 0 || len >= sizeof (name)) {
				return (scf_set_error(
				    SCF_ERROR_INVALID_ARGUMENT));
			}
			(void) pthread_mutex_lock(&handle->rh_lock);
			(void) strlcpy(handle->rh_doorpath, name,
			    sizeof (handle->rh_doorpath));
			(void) pthread_mutex_unlock(&handle->rh_lock);
		}
		return (0);
	}

	if (strcmp(name, "zone") == 0) {
		char zone[MAXPATHLEN], root[MAXPATHLEN], door[MAXPATHLEN];
		static int (*zone_get_rootpath)(char *, char *, size_t);
		ssize_t len;

		/*
		 * In order to be able to set the zone on a handle, we want
		 * to determine the zone's path, which requires us to call into
		 * libzonecfg -- but libzonecfg.so links against libscf.so so
		 * we must not explicitly link to it.  To circumvent the
		 * circular dependency, we will pull it in here via dlopen().
		 */
		if (zone_get_rootpath == NULL) {
			void *dl = dlopen("libzonecfg.so.1", RTLD_LAZY), *sym;

			if (dl == NULL)
				return (scf_set_error(SCF_ERROR_NOT_FOUND));

			if ((sym = dlsym(dl, "zone_get_rootpath")) == NULL) {
				(void) dlclose(dl);
				return (scf_set_error(SCF_ERROR_INTERNAL));
			}

			zone_get_rootpath = (int(*)(char *, char *, size_t))sym;
		}

		if (v == SCF_DECORATE_CLEAR) {
			(void) pthread_mutex_lock(&handle->rh_lock);
			handle->rh_doorpath[0] = 0;
			(void) pthread_mutex_unlock(&handle->rh_lock);

			return (0);
		}

		if ((len = scf_value_get_astring(v, zone, sizeof (zone))) < 0)
			return (-1);

		if (len == 0 || len >= sizeof (zone))
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

		if (zone_get_rootpath(zone, root, sizeof (root)) != Z_OK) {
			if (strcmp(zone, GLOBAL_ZONENAME) == 0) {
				root[0] = '\0';
			} else {
				return (scf_set_error(SCF_ERROR_NOT_FOUND));
			}
		}

		if (snprintf(door, sizeof (door), "%s/%s", root,
		    default_door_path) >= sizeof (door))
			return (scf_set_error(SCF_ERROR_INTERNAL));

		(void) pthread_mutex_lock(&handle->rh_lock);
		(void) strlcpy(handle->rh_doorpath, door,
		    sizeof (handle->rh_doorpath));
		(void) pthread_mutex_unlock(&handle->rh_lock);

		return (0);
	}

	return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
}

/*
 * fails with INVALID_ARGUMENT and HANDLE_MISMATCH.
 */
int
_scf_handle_decorations(scf_handle_t *handle, scf_decoration_func *f,
    scf_value_t *v, void *data)
{
	scf_decoration_info_t i;
	char name[sizeof (handle->rh_doorpath)];
	uint64_t debug;

	if (f == NULL || v == NULL)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	if (v->value_handle != handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	i.sdi_name = (const char *)"debug";
	i.sdi_type = SCF_TYPE_COUNT;
	(void) pthread_mutex_lock(&handle->rh_lock);
	debug = handle->rh_debug;
	(void) pthread_mutex_unlock(&handle->rh_lock);
	if (debug != 0) {
		scf_value_set_count(v, debug);
		i.sdi_value = v;
	} else {
		i.sdi_value = SCF_DECORATE_CLEAR;
	}

	if ((*f)(&i, data) == 0)
		return (0);

	i.sdi_name = (const char *)"door_path";
	i.sdi_type = SCF_TYPE_ASTRING;
	(void) pthread_mutex_lock(&handle->rh_lock);
	(void) strlcpy(name, handle->rh_doorpath, sizeof (name));
	(void) pthread_mutex_unlock(&handle->rh_lock);
	if (name[0] != 0) {
		(void) scf_value_set_astring(v, name);
		i.sdi_value = v;
	} else {
		i.sdi_value = SCF_DECORATE_CLEAR;
	}

	if ((*f)(&i, data) == 0)
		return (0);

	return (1);
}

/*
 * Fails if handle is not bound.
 */
static int
handle_unbind_unlocked(scf_handle_t *handle)
{
	rep_protocol_request_t request;
	rep_protocol_response_t response;

	if (!handle_is_bound(handle))
		return (-1);

	request.rpr_request = REP_PROTOCOL_CLOSE;

	(void) make_door_call(handle, &request, sizeof (request),
	    &response, sizeof (response));

	handle_do_close(handle);

	return (SCF_SUCCESS);
}

/*
 * Fails with
 *   _HANDLE_DESTROYED - dp's handle has been destroyed
 *   _INTERNAL - server response too big
 *		 entity already set up with different type
 *   _NO_RESOURCES - server out of memory
 */
static int
datael_attach(scf_datael_t *dp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_setup request;
	rep_protocol_response_t response;
	ssize_t r;

	assert(MUTEX_HELD(&h->rh_lock));

	dp->rd_reset = 0;		/* setup implicitly resets */

	if (h->rh_flags & HANDLE_DEAD)
		return (scf_set_error(SCF_ERROR_HANDLE_DESTROYED));

	if (!handle_is_bound(h))
		return (SCF_SUCCESS);		/* nothing to do */

	request.rpr_request = REP_PROTOCOL_ENTITY_SETUP;
	request.rpr_entityid = dp->rd_entity;
	request.rpr_entitytype = dp->rd_type;

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r == NOT_BOUND || r == CALL_FAILED)
		return (SCF_SUCCESS);
	if (r == RESULT_TOO_BIG)
		return (scf_set_error(SCF_ERROR_INTERNAL));

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

/*
 * Fails with
 *   _HANDLE_DESTROYED - iter's handle has been destroyed
 *   _INTERNAL - server response too big
 *		 iter already existed
 *   _NO_RESOURCES
 */
static int
iter_attach(scf_iter_t *iter)
{
	scf_handle_t *h = iter->iter_handle;
	struct rep_protocol_iter_request request;
	struct rep_protocol_response response;
	int r;

	assert(MUTEX_HELD(&h->rh_lock));

	if (h->rh_flags & HANDLE_DEAD)
		return (scf_set_error(SCF_ERROR_HANDLE_DESTROYED));

	if (!handle_is_bound(h))
		return (SCF_SUCCESS);		/* nothing to do */

	request.rpr_request = REP_PROTOCOL_ITER_SETUP;
	request.rpr_iterid = iter->iter_id;

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r == NOT_BOUND || r == CALL_FAILED)
		return (SCF_SUCCESS);
	if (r == RESULT_TOO_BIG)
		return (scf_set_error(SCF_ERROR_INTERNAL));

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

/*
 * Fails with
 *   _IN_USE - handle already bound
 *   _NO_SERVER - server door could not be open()ed
 *		  door call failed
 *		  door_info() failed
 *   _VERSION_MISMATCH - server returned bad file descriptor
 *			 server claimed bad request
 *			 server reported version mismatch
 *			 server refused with unknown reason
 *   _INVALID_ARGUMENT
 *   _NO_RESOURCES - server is out of memory
 *   _PERMISSION_DENIED
 *   _INTERNAL - could not set up entities or iters
 *		 server response too big
 *
 * perhaps this should try multiple times.
 */
int
scf_handle_bind(scf_handle_t *handle)
{
	scf_datael_t *el;
	scf_iter_t *iter;

	pid_t pid;
	int fd;
	int res;
	door_info_t info;
	repository_door_request_t request;
	repository_door_response_t response;
	const char *door_name = default_door_path;

	(void) pthread_mutex_lock(&handle->rh_lock);
	if (handle_is_bound(handle)) {
		(void) pthread_mutex_unlock(&handle->rh_lock);
		return (scf_set_error(SCF_ERROR_IN_USE));
	}

	/* wait until any active fd users have cleared out */
	while (handle->rh_fd_users > 0) {
		int cancel_state;

		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
		    &cancel_state);
		(void) pthread_cond_wait(&handle->rh_cv, &handle->rh_lock);
		(void) pthread_setcancelstate(cancel_state, NULL);
	}

	/* check again, since we had to drop the lock */
	if (handle_is_bound(handle)) {
		(void) pthread_mutex_unlock(&handle->rh_lock);
		return (scf_set_error(SCF_ERROR_IN_USE));
	}

	assert(handle->rh_doorfd == -1 && handle->rh_doorfd_old == -1);

	if (handle->rh_doorpath[0] != 0)
		door_name = handle->rh_doorpath;

	fd = open(door_name, O_RDONLY, 0);
	if (fd == -1) {
		(void) pthread_mutex_unlock(&handle->rh_lock);
		return (scf_set_error(SCF_ERROR_NO_SERVER));
	}

	request.rdr_version = REPOSITORY_DOOR_VERSION;
	request.rdr_request = REPOSITORY_DOOR_REQUEST_CONNECT;
	request.rdr_flags = handle->rh_flags;
	request.rdr_debug = handle->rh_debug;

	pid = getpid();

	res = make_door_call_retfd(fd, &request, sizeof (request),
	    &response, sizeof (response), &handle->rh_doorfd);

	(void) close(fd);

	if (res < 0) {
		(void) pthread_mutex_unlock(&handle->rh_lock);

		assert(res != NOT_BOUND);
		if (res == CALL_FAILED)
			return (scf_set_error(SCF_ERROR_NO_SERVER));
		assert(res == RESULT_TOO_BIG);
		return (scf_set_error(SCF_ERROR_INTERNAL));
	}

	if (handle->rh_doorfd < 0) {
		(void) pthread_mutex_unlock(&handle->rh_lock);

		switch (response.rdr_status) {
		case REPOSITORY_DOOR_SUCCESS:
			return (scf_set_error(SCF_ERROR_VERSION_MISMATCH));

		case REPOSITORY_DOOR_FAIL_BAD_REQUEST:
			return (scf_set_error(SCF_ERROR_VERSION_MISMATCH));

		case REPOSITORY_DOOR_FAIL_VERSION_MISMATCH:
			return (scf_set_error(SCF_ERROR_VERSION_MISMATCH));

		case REPOSITORY_DOOR_FAIL_BAD_FLAG:
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

		case REPOSITORY_DOOR_FAIL_NO_RESOURCES:
			return (scf_set_error(SCF_ERROR_NO_RESOURCES));

		case REPOSITORY_DOOR_FAIL_PERMISSION_DENIED:
			return (scf_set_error(SCF_ERROR_PERMISSION_DENIED));

		default:
			return (scf_set_error(SCF_ERROR_VERSION_MISMATCH));
		}
	}

	(void) fcntl(handle->rh_doorfd, F_SETFD, FD_CLOEXEC);

	if (door_info(handle->rh_doorfd, &info) < 0) {
		(void) close(handle->rh_doorfd);
		handle->rh_doorfd = -1;

		(void) pthread_mutex_unlock(&handle->rh_lock);
		return (scf_set_error(SCF_ERROR_NO_SERVER));
	}

	handle->rh_doorpid = pid;
	handle->rh_doorid = info.di_uniquifier;

	/*
	 * Now, re-attach everything
	 */
	for (el = uu_list_first(handle->rh_dataels); el != NULL;
	    el = uu_list_next(handle->rh_dataels, el)) {
		if (datael_attach(el) == -1) {
			assert(scf_error() != SCF_ERROR_HANDLE_DESTROYED);
			(void) handle_unbind_unlocked(handle);
			(void) pthread_mutex_unlock(&handle->rh_lock);
			return (-1);
		}
	}

	for (iter = uu_list_first(handle->rh_iters); iter != NULL;
	    iter = uu_list_next(handle->rh_iters, iter)) {
		if (iter_attach(iter) == -1) {
			assert(scf_error() != SCF_ERROR_HANDLE_DESTROYED);
			(void) handle_unbind_unlocked(handle);
			(void) pthread_mutex_unlock(&handle->rh_lock);
			return (-1);
		}
	}
	(void) pthread_mutex_unlock(&handle->rh_lock);
	return (SCF_SUCCESS);
}

int
scf_handle_unbind(scf_handle_t *handle)
{
	int ret;
	(void) pthread_mutex_lock(&handle->rh_lock);
	ret = handle_unbind_unlocked(handle);
	(void) pthread_mutex_unlock(&handle->rh_lock);
	return (ret == SCF_SUCCESS ? ret : scf_set_error(SCF_ERROR_NOT_BOUND));
}

static scf_handle_t *
handle_get(scf_handle_t *h)
{
	(void) pthread_mutex_lock(&h->rh_lock);
	if (h->rh_flags & HANDLE_DEAD) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		(void) scf_set_error(SCF_ERROR_HANDLE_DESTROYED);
		return (NULL);
	}
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (h);
}

/*
 * Called when an object is removed from the handle.  On the last remove,
 * cleans up and frees the handle.
 */
static void
handle_unrefed(scf_handle_t *handle)
{
	scf_iter_t *iter;
	scf_value_t *v;
	scf_scope_t *sc;
	scf_service_t *svc;
	scf_instance_t *inst;
	scf_snapshot_t *snap;
	scf_snaplevel_t *snaplvl;
	scf_propertygroup_t *pg;
	scf_property_t *prop;

	assert(MUTEX_HELD(&handle->rh_lock));

	/*
	 * Don't do anything if the handle has not yet been destroyed, there
	 * are still external references, or we're already doing unrefed
	 * handling.
	 */
	if (!(handle->rh_flags & HANDLE_DEAD) ||
	    handle->rh_extrefs > 0 ||
	    handle->rh_fd_users > 0 ||
	    (handle->rh_flags & HANDLE_UNREFED)) {
		(void) pthread_mutex_unlock(&handle->rh_lock);
		return;
	}

	handle->rh_flags |= HANDLE_UNREFED;

	/*
	 * Now that we know that there are no external references, and the
	 * HANDLE_DEAD flag keeps new ones from appearing, we can clean up
	 * our subhandles and destroy the handle completely.
	 */
	assert(handle->rh_intrefs >= 0);
	handle->rh_extrefs = handle->rh_intrefs;
	handle->rh_intrefs = 0;
	(void) pthread_mutex_unlock(&handle->rh_lock);

	handle_hold_subhandles(handle, RH_HOLD_ALL);

	iter = handle->rh_iter;
	sc = handle->rh_scope;
	svc = handle->rh_service;
	inst = handle->rh_instance;
	snap = handle->rh_snapshot;
	snaplvl = handle->rh_snaplvl;
	pg = handle->rh_pg;
	prop = handle->rh_property;
	v = handle->rh_value;

	handle->rh_iter = NULL;
	handle->rh_scope = NULL;
	handle->rh_service = NULL;
	handle->rh_instance = NULL;
	handle->rh_snapshot = NULL;
	handle->rh_snaplvl = NULL;
	handle->rh_pg = NULL;
	handle->rh_property = NULL;
	handle->rh_value = NULL;

	if (iter != NULL)
		scf_iter_destroy(iter);
	if (sc != NULL)
		scf_scope_destroy(sc);
	if (svc != NULL)
		scf_service_destroy(svc);
	if (inst != NULL)
		scf_instance_destroy(inst);
	if (snap != NULL)
		scf_snapshot_destroy(snap);
	if (snaplvl != NULL)
		scf_snaplevel_destroy(snaplvl);
	if (pg != NULL)
		scf_pg_destroy(pg);
	if (prop != NULL)
		scf_property_destroy(prop);
	if (v != NULL)
		scf_value_destroy(v);

	(void) pthread_mutex_lock(&handle->rh_lock);

	/* there should be no outstanding children at this point */
	assert(handle->rh_extrefs == 0);
	assert(handle->rh_intrefs == 0);
	assert(handle->rh_values == 0);
	assert(handle->rh_entries == 0);
	assert(uu_list_numnodes(handle->rh_dataels) == 0);
	assert(uu_list_numnodes(handle->rh_iters) == 0);

	uu_list_destroy(handle->rh_dataels);
	uu_list_destroy(handle->rh_iters);
	handle->rh_dataels = NULL;
	handle->rh_iters = NULL;
	(void) pthread_mutex_unlock(&handle->rh_lock);

	(void) pthread_mutex_destroy(&handle->rh_lock);

	uu_free(handle);
}

void
scf_handle_destroy(scf_handle_t *handle)
{
	if (handle == NULL)
		return;

	(void) pthread_mutex_lock(&handle->rh_lock);
	if (handle->rh_flags & HANDLE_DEAD) {
		/*
		 * This is an error (you are not allowed to reference the
		 * handle after it is destroyed), but we can't report it.
		 */
		(void) pthread_mutex_unlock(&handle->rh_lock);
		return;
	}
	handle->rh_flags |= HANDLE_DEAD;
	(void) handle_unbind_unlocked(handle);
	handle_unrefed(handle);
}

ssize_t
scf_myname(scf_handle_t *h, char *out, size_t len)
{
	char *cp;

	if (!handle_has_server(h))
		return (scf_set_error(SCF_ERROR_CONNECTION_BROKEN));

	cp = getenv("SMF_FMRI");
	if (cp == NULL)
		return (scf_set_error(SCF_ERROR_NOT_SET));

	return (strlcpy(out, cp, len));
}

static uint32_t
handle_alloc_entityid(scf_handle_t *h)
{
	uint32_t nextid;

	assert(MUTEX_HELD(&h->rh_lock));

	if (uu_list_numnodes(h->rh_dataels) == UINT32_MAX)
		return (0);		/* no ids available */

	/*
	 * The following loop assumes that there are not a huge number of
	 * outstanding entities when we've wrapped.  If that ends up not
	 * being the case, the O(N^2) nature of this search will hurt a lot,
	 * and the data structure should be switched to an AVL tree.
	 */
	nextid = h->rh_nextentity + 1;
	for (;;) {
		scf_datael_t *cur;

		if (nextid == 0) {
			nextid++;
			h->rh_flags |= HANDLE_WRAPPED_ENTITY;
		}
		if (!(h->rh_flags & HANDLE_WRAPPED_ENTITY))
			break;

		cur = uu_list_find(h->rh_dataels, NULL, &nextid, NULL);
		if (cur == NULL)
			break;		/* not in use */

		if (nextid == h->rh_nextentity)
			return (0);	/* wrapped around; no ids available */
		nextid++;
	}

	h->rh_nextentity = nextid;
	return (nextid);
}

static uint32_t
handle_alloc_iterid(scf_handle_t *h)
{
	uint32_t nextid;

	assert(MUTEX_HELD(&h->rh_lock));

	if (uu_list_numnodes(h->rh_iters) == UINT32_MAX)
		return (0);		/* no ids available */

	/* see the comment in handle_alloc_entityid */
	nextid = h->rh_nextiter + 1;
	for (;;) {
		scf_iter_t *cur;

		if (nextid == 0) {
			nextid++;
			h->rh_flags |= HANDLE_WRAPPED_ITER;
		}
		if (!(h->rh_flags & HANDLE_WRAPPED_ITER))
			break;			/* not yet wrapped */

		cur = uu_list_find(h->rh_iters, NULL, &nextid, NULL);
		if (cur == NULL)
			break;		/* not in use */

		if (nextid == h->rh_nextiter)
			return (0);	/* wrapped around; no ids available */
		nextid++;
	}

	h->rh_nextiter = nextid;
	return (nextid);
}

static uint32_t
handle_next_changeid(scf_handle_t *handle)
{
	uint32_t nextid;

	assert(MUTEX_HELD(&handle->rh_lock));

	nextid = ++handle->rh_nextchangeid;
	if (nextid == 0)
		nextid = ++handle->rh_nextchangeid;
	return (nextid);
}

/*
 * Fails with
 *   _INVALID_ARGUMENT - h is NULL
 *   _HANDLE_DESTROYED
 *   _INTERNAL - server response too big
 *		 entity already set up with different type
 *   _NO_RESOURCES
 */
static int
datael_init(scf_datael_t *dp, scf_handle_t *h, uint32_t type)
{
	int ret;

	if (h == NULL)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	uu_list_node_init(dp, &dp->rd_node, datael_pool);

	dp->rd_handle = h;
	dp->rd_type = type;
	dp->rd_reset = 0;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (h->rh_flags & HANDLE_DEAD) {
		/*
		 * we're in undefined territory (the user cannot use a handle
		 * directly after it has been destroyed), but we don't want
		 * to allow any new references to happen, so we fail here.
		 */
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_HANDLE_DESTROYED));
	}
	dp->rd_entity = handle_alloc_entityid(h);
	if (dp->rd_entity == 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		uu_list_node_fini(dp, &dp->rd_node, datael_pool);
		return (scf_set_error(SCF_ERROR_NO_MEMORY));
	}

	ret = datael_attach(dp);
	if (ret == 0) {
		(void) uu_list_insert_before(h->rh_dataels, NULL, dp);
		h->rh_extrefs++;
	} else {
		uu_list_node_fini(dp, &dp->rd_node, datael_pool);
	}
	(void) pthread_mutex_unlock(&h->rh_lock);

	return (ret);
}

static void
datael_destroy(scf_datael_t *dp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_teardown request;
	rep_protocol_response_t response;

	(void) pthread_mutex_lock(&h->rh_lock);
	uu_list_remove(h->rh_dataels, dp);
	--h->rh_extrefs;

	if (handle_is_bound(h)) {
		request.rpr_request = REP_PROTOCOL_ENTITY_TEARDOWN;
		request.rpr_entityid = dp->rd_entity;

		(void) make_door_call(h, &request, sizeof (request),
		    &response, sizeof (response));
	}
	handle_unrefed(h);			/* drops h->rh_lock */

	dp->rd_handle = NULL;
}

static scf_handle_t *
datael_handle(const scf_datael_t *dp)
{
	return (handle_get(dp->rd_handle));
}

/*
 * We delay ENTITY_RESETs until right before the entity is used.  By doing
 * them lazily, we remove quite a few unnecessary calls.
 */
static void
datael_do_reset_locked(scf_datael_t *dp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_reset request;
	rep_protocol_response_t response;

	assert(MUTEX_HELD(&h->rh_lock));

	request.rpr_request = REP_PROTOCOL_ENTITY_RESET;
	request.rpr_entityid = dp->rd_entity;

	(void) make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	dp->rd_reset = 0;
}

static void
datael_reset_locked(scf_datael_t *dp)
{
	assert(MUTEX_HELD(&dp->rd_handle->rh_lock));
	dp->rd_reset = 1;
}

static void
datael_reset(scf_datael_t *dp)
{
	scf_handle_t *h = dp->rd_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	dp->rd_reset = 1;
	(void) pthread_mutex_unlock(&h->rh_lock);
}

static void
datael_finish_reset(const scf_datael_t *dp_arg)
{
	scf_datael_t *dp = (scf_datael_t *)dp_arg;

	if (dp->rd_reset)
		datael_do_reset_locked(dp);
}

/*
 * Fails with _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL (server response too
 * big, bad entity id, request not applicable to entity, name too long for
 * buffer), _NOT_SET, _DELETED, or _CONSTRAINT_VIOLATED (snaplevel is not of an
 * instance).
 */
static ssize_t
datael_get_name(const scf_datael_t *dp, char *buf, size_t size, uint32_t type)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_name request;
	struct rep_protocol_name_response response;
	ssize_t r;

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ENTITY_NAME;
	request.rpr_entityid = dp->rd_entity;
	request.rpr_answertype = type;

	datael_finish_reset(dp);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		assert(response.rpr_response != REP_PROTOCOL_FAIL_BAD_REQUEST);
		if (response.rpr_response == REP_PROTOCOL_FAIL_NOT_FOUND)
			return (scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED));
		return (scf_set_error(proto_error(response.rpr_response)));
	}
	return (strlcpy(buf, response.rpr_name, size));
}

/*
 * Fails with _HANDLE_MISMATCH, _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL
 * (server response too big, bad element id), _EXISTS (elements have same id),
 * _NOT_SET, _DELETED, _CONSTRAINT_VIOLATED, _NOT_FOUND (scope has no parent),
 * or _SUCCESS.
 */
static int
datael_get_parent(const scf_datael_t *dp, scf_datael_t *pp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_parent request;
	struct rep_protocol_response response;

	ssize_t r;

	if (h != pp->rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ENTITY_GET_PARENT;
	request.rpr_entityid = dp->rd_entity;
	request.rpr_outid = pp->rd_entity;

	datael_finish_reset(dp);
	datael_finish_reset(pp);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		if (response.rpr_response == REP_PROTOCOL_FAIL_TYPE_MISMATCH)
			return (scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED));
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	return (SCF_SUCCESS);
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT (out does not have type type,
 * name is invalid), _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL (server response
 * too big, bad id, iter already exists, element cannot have children of type,
 * type is invalid, iter was reset, sequence was bad, iter walks values, iter
 * does not walk type entities), _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
static int
datael_get_child_composed_locked(const scf_datael_t *dp, const char *name,
    uint32_t type, scf_datael_t *out, scf_iter_t *iter)
{
	struct rep_protocol_iter_start request;
	struct rep_protocol_iter_read read_request;
	struct rep_protocol_response response;

	scf_handle_t *h = dp->rd_handle;
	ssize_t r;

	if (h != out->rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (out->rd_type != type)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	assert(MUTEX_HELD(&h->rh_lock));
	assert(iter != NULL);

	scf_iter_reset_locked(iter);
	iter->iter_type = type;

	request.rpr_request = REP_PROTOCOL_ITER_START;
	request.rpr_iterid = iter->iter_id;
	request.rpr_entity = dp->rd_entity;
	request.rpr_itertype = type;
	request.rpr_flags = RP_ITER_START_EXACT | RP_ITER_START_COMPOSED;

	if (name == NULL || strlcpy(request.rpr_pattern, name,
	    sizeof (request.rpr_pattern)) >= sizeof (request.rpr_pattern)) {
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	datael_finish_reset(dp);
	datael_finish_reset(out);

	/*
	 * We hold the handle lock across both door calls, so that they
	 * appear atomic.
	 */
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	iter->iter_sequence++;

	read_request.rpr_request = REP_PROTOCOL_ITER_READ;
	read_request.rpr_iterid = iter->iter_id;
	read_request.rpr_sequence = iter->iter_sequence;
	read_request.rpr_entityid = out->rd_entity;

	r = make_door_call(h, &read_request, sizeof (read_request),
	    &response, sizeof (response));

	scf_iter_reset_locked(iter);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response == REP_PROTOCOL_DONE) {
		return (scf_set_error(SCF_ERROR_NOT_FOUND));
	}

	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		if (response.rpr_response == REP_PROTOCOL_FAIL_NOT_SET ||
		    response.rpr_response == REP_PROTOCOL_FAIL_BAD_REQUEST)
			return (scf_set_error(SCF_ERROR_INTERNAL));
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	return (0);
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT (out does not have type type,
 * name is invalid), _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL (server response
 * too big, bad id, element cannot have children of type, type is invalid),
 * _NOT_SET, _DELETED, _NO_RESOURCES, _BACKEND_ACCESS.
 */
static int
datael_get_child_locked(const scf_datael_t *dp, const char *name,
    uint32_t type, scf_datael_t *out)
{
	struct rep_protocol_entity_get_child request;
	struct rep_protocol_response response;

	scf_handle_t *h = dp->rd_handle;
	ssize_t r;

	if (h != out->rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (out->rd_type != type)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	assert(MUTEX_HELD(&h->rh_lock));

	request.rpr_request = REP_PROTOCOL_ENTITY_GET_CHILD;
	request.rpr_entityid = dp->rd_entity;
	request.rpr_childid = out->rd_entity;

	if (name == NULL || strlcpy(request.rpr_name, name,
	    sizeof (request.rpr_name)) >= sizeof (request.rpr_name)) {
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	datael_finish_reset(dp);
	datael_finish_reset(out);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));
	return (0);
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT (out does not have type type,
 * name is invalid), _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL (server response
 * too big, bad id, iter already exists, element cannot have children of type,
 * type is invalid, iter was reset, sequence was bad, iter walks values, iter
 * does not walk type entities), _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
static int
datael_get_child(const scf_datael_t *dp, const char *name, uint32_t type,
    scf_datael_t *out, boolean_t composed)
{
	scf_handle_t *h = dp->rd_handle;
	uint32_t held = 0;
	int ret;

	scf_iter_t *iter = NULL;

	if (composed)
		iter = HANDLE_HOLD_ITER(h);

	if (out == NULL) {
		switch (type) {
		case REP_PROTOCOL_ENTITY_SERVICE:
			out = &HANDLE_HOLD_SERVICE(h)->rd_d;
			held = RH_HOLD_SERVICE;
			break;

		case REP_PROTOCOL_ENTITY_INSTANCE:
			out = &HANDLE_HOLD_INSTANCE(h)->rd_d;
			held = RH_HOLD_INSTANCE;
			break;

		case REP_PROTOCOL_ENTITY_SNAPSHOT:
			out = &HANDLE_HOLD_SNAPSHOT(h)->rd_d;
			held = RH_HOLD_SNAPSHOT;
			break;

		case REP_PROTOCOL_ENTITY_SNAPLEVEL:
			out = &HANDLE_HOLD_SNAPLVL(h)->rd_d;
			held = RH_HOLD_SNAPLVL;
			break;

		case REP_PROTOCOL_ENTITY_PROPERTYGRP:
			out = &HANDLE_HOLD_PG(h)->rd_d;
			held = RH_HOLD_PG;
			break;

		case REP_PROTOCOL_ENTITY_PROPERTY:
			out = &HANDLE_HOLD_PROPERTY(h)->rd_d;
			held = RH_HOLD_PROPERTY;
			break;

		default:
			assert(0);
			abort();
		}
	}

	(void) pthread_mutex_lock(&h->rh_lock);
	if (composed)
		ret = datael_get_child_composed_locked(dp, name, type, out,
		    iter);
	else
		ret = datael_get_child_locked(dp, name, type, out);
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (composed)
		HANDLE_RELE_ITER(h);

	if (held)
		handle_rele_subhandles(h, held);

	return (ret);
}

/*
 * Fails with
 *   _HANDLE_MISMATCH
 *   _INVALID_ARGUMENT - name is too long
 *			 invalid changeid
 *			 name is invalid
 *			 cannot create children for dp's type of node
 *   _NOT_BOUND - handle is not bound
 *   _CONNECTION_BROKEN - server is not reachable
 *   _INTERNAL - server response too big
 *		 dp or cp has unknown id
 *		 type is _PROPERTYGRP
 *		 type is invalid
 *		 dp cannot have children of type type
 *		 database is corrupt
 *   _EXISTS - dp & cp have the same id
 *   _EXISTS - child already exists
 *   _DELETED - dp has been deleted
 *   _NOT_SET - dp is reset
 *   _NO_RESOURCES
 *   _PERMISSION_DENIED
 *   _BACKEND_ACCESS
 *   _BACKEND_READONLY
 */
static int
datael_add_child(const scf_datael_t *dp, const char *name, uint32_t type,
    scf_datael_t *cp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_create_child request;
	struct rep_protocol_response response;
	ssize_t r;
	uint32_t held = 0;

	if (cp == NULL) {
		switch (type) {
		case REP_PROTOCOL_ENTITY_SCOPE:
			cp = &HANDLE_HOLD_SCOPE(h)->rd_d;
			held = RH_HOLD_SCOPE;
			break;
		case REP_PROTOCOL_ENTITY_SERVICE:
			cp = &HANDLE_HOLD_SERVICE(h)->rd_d;
			held = RH_HOLD_SERVICE;
			break;
		case REP_PROTOCOL_ENTITY_INSTANCE:
			cp = &HANDLE_HOLD_INSTANCE(h)->rd_d;
			held = RH_HOLD_INSTANCE;
			break;
		case REP_PROTOCOL_ENTITY_SNAPSHOT:
		default:
			assert(0);
			abort();
		}
		assert(h == cp->rd_handle);

	} else if (h != cp->rd_handle) {
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));
	}

	if (strlcpy(request.rpr_name, name, sizeof (request.rpr_name)) >=
	    sizeof (request.rpr_name)) {
		r = scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto err;
	}

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ENTITY_CREATE_CHILD;
	request.rpr_entityid = dp->rd_entity;
	request.rpr_childtype = type;
	request.rpr_childid = cp->rd_entity;

	datael_finish_reset(dp);
	request.rpr_changeid = handle_next_changeid(h);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (held)
		handle_rele_subhandles(h, held);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);

err:
	if (held)
		handle_rele_subhandles(h, held);
	return (r);
}

static int
datael_add_pg(const scf_datael_t *dp, const char *name, const char *type,
    uint32_t flags, scf_datael_t *cp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_create_pg request;
	struct rep_protocol_response response;
	ssize_t r;

	int holding_els = 0;

	if (cp == NULL) {
		holding_els = 1;
		cp = &HANDLE_HOLD_PG(h)->rd_d;
		assert(h == cp->rd_handle);

	} else if (h != cp->rd_handle) {
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));
	}

	request.rpr_request = REP_PROTOCOL_ENTITY_CREATE_PG;

	if (name == NULL || strlcpy(request.rpr_name, name,
	    sizeof (request.rpr_name)) > sizeof (request.rpr_name)) {
		r = scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto err;
	}

	if (type == NULL || strlcpy(request.rpr_type, type,
	    sizeof (request.rpr_type)) > sizeof (request.rpr_type)) {
		r = scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto err;
	}

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_entityid = dp->rd_entity;
	request.rpr_childid = cp->rd_entity;
	request.rpr_flags = flags;

	datael_finish_reset(dp);
	datael_finish_reset(cp);
	request.rpr_changeid = handle_next_changeid(h);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (holding_els)
		HANDLE_RELE_PG(h);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);

err:
	if (holding_els)
		HANDLE_RELE_PG(h);
	return (r);
}

static int
datael_delete(const scf_datael_t *dp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_delete request;
	struct rep_protocol_response response;
	ssize_t r;

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ENTITY_DELETE;
	request.rpr_entityid = dp->rd_entity;

	datael_finish_reset(dp);
	request.rpr_changeid = handle_next_changeid(h);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

/*
 * Fails with
 *   _INVALID_ARGUMENT - h is NULL
 *   _NO_MEMORY
 *   _HANDLE_DESTROYED - h has been destroyed
 *   _INTERNAL - server response too big
 *		 iter already exists
 *   _NO_RESOURCES
 */
scf_iter_t *
scf_iter_create(scf_handle_t *h)
{
	scf_iter_t *iter;

	if (h == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}

	iter = uu_zalloc(sizeof (*iter));
	if (iter == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	uu_list_node_init(iter, &iter->iter_node, iter_pool);
	iter->iter_handle = h;
	iter->iter_sequence = 1;
	iter->iter_type = REP_PROTOCOL_ENTITY_NONE;

	(void) pthread_mutex_lock(&h->rh_lock);
	iter->iter_id = handle_alloc_iterid(h);
	if (iter->iter_id == 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		uu_list_node_fini(iter, &iter->iter_node, iter_pool);
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		uu_free(iter);
		return (NULL);
	}
	if (iter_attach(iter) == -1) {
		uu_list_node_fini(iter, &iter->iter_node, iter_pool);
		(void) pthread_mutex_unlock(&h->rh_lock);
		uu_free(iter);
		return (NULL);
	}
	(void) uu_list_insert_before(h->rh_iters, NULL, iter);
	h->rh_extrefs++;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (iter);
}

scf_handle_t *
scf_iter_handle(const scf_iter_t *iter)
{
	return (handle_get(iter->iter_handle));
}

static void
scf_iter_reset_locked(scf_iter_t *iter)
{
	struct rep_protocol_iter_request request;
	struct rep_protocol_response response;

	request.rpr_request = REP_PROTOCOL_ITER_RESET;
	request.rpr_iterid = iter->iter_id;

	assert(MUTEX_HELD(&iter->iter_handle->rh_lock));

	(void) make_door_call(iter->iter_handle,
	    &request, sizeof (request), &response, sizeof (response));

	iter->iter_type = REP_PROTOCOL_ENTITY_NONE;
	iter->iter_sequence = 1;
}

void
scf_iter_reset(scf_iter_t *iter)
{
	(void) pthread_mutex_lock(&iter->iter_handle->rh_lock);
	scf_iter_reset_locked(iter);
	(void) pthread_mutex_unlock(&iter->iter_handle->rh_lock);
}

void
scf_iter_destroy(scf_iter_t *iter)
{
	scf_handle_t *handle;

	struct rep_protocol_iter_request request;
	struct rep_protocol_response response;

	if (iter == NULL)
		return;

	handle = iter->iter_handle;

	(void) pthread_mutex_lock(&handle->rh_lock);
	request.rpr_request = REP_PROTOCOL_ITER_TEARDOWN;
	request.rpr_iterid = iter->iter_id;

	(void) make_door_call(handle, &request, sizeof (request),
	    &response, sizeof (response));

	uu_list_remove(handle->rh_iters, iter);
	--handle->rh_extrefs;
	handle_unrefed(handle);			/* drops h->rh_lock */
	iter->iter_handle = NULL;

	uu_list_node_fini(iter, &iter->iter_node, iter_pool);
	uu_free(iter);
}

static int
handle_get_local_scope_locked(scf_handle_t *handle, scf_scope_t *out)
{
	struct rep_protocol_entity_get request;
	struct rep_protocol_name_response response;
	ssize_t r;

	assert(MUTEX_HELD(&handle->rh_lock));

	if (handle != out->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	request.rpr_request = REP_PROTOCOL_ENTITY_GET;
	request.rpr_entityid = out->rd_d.rd_entity;
	request.rpr_object = RP_ENTITY_GET_MOST_LOCAL_SCOPE;

	datael_finish_reset(&out->rd_d);
	r = make_door_call(handle, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

int
scf_iter_handle_scopes(scf_iter_t *iter, const scf_handle_t *handle)
{
	scf_handle_t *h = iter->iter_handle;
	if (h != handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_iter_reset_locked(iter);

	if (!handle_is_bound(h)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_NOT_BOUND));
	}

	if (!handle_has_server_locked(h)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_CONNECTION_BROKEN));
	}

	iter->iter_type = REP_PROTOCOL_ENTITY_SCOPE;
	iter->iter_sequence = 1;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (0);
}

int
scf_iter_next_scope(scf_iter_t *iter, scf_scope_t *out)
{
	int ret;
	scf_handle_t *h = iter->iter_handle;

	if (h != out->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	if (iter->iter_type == REP_PROTOCOL_ENTITY_NONE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_NOT_SET));
	}
	if (iter->iter_type != REP_PROTOCOL_ENTITY_SCOPE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	if (iter->iter_sequence == 1) {
		if ((ret = handle_get_local_scope_locked(h, out)) ==
		    SCF_SUCCESS) {
			iter->iter_sequence++;
			ret = 1;
		}
	} else {
		datael_reset_locked(&out->rd_d);
		ret = 0;
	}
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (ret);
}

int
scf_handle_get_scope(scf_handle_t *h, const char *name, scf_scope_t *out)
{
	int ret;

	if (h != out->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	if (strcmp(name, SCF_SCOPE_LOCAL) == 0) {
		ret = handle_get_local_scope_locked(h, out);
	} else {
		datael_reset_locked(&out->rd_d);
		if (uu_check_name(name, 0) == -1)
			ret = scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		else
			ret = scf_set_error(SCF_ERROR_NOT_FOUND);
	}
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (ret);
}

static int
datael_setup_iter(scf_iter_t *iter, const scf_datael_t *dp, uint32_t res_type,
    boolean_t composed)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_iter_start request;
	struct rep_protocol_response response;

	ssize_t r;

	if (h != iter->iter_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_iter_reset_locked(iter);
	iter->iter_type = res_type;

	request.rpr_request = REP_PROTOCOL_ITER_START;
	request.rpr_iterid = iter->iter_id;
	request.rpr_entity = dp->rd_entity;
	request.rpr_itertype = res_type;
	request.rpr_flags = RP_ITER_START_ALL |
	    (composed ? RP_ITER_START_COMPOSED : 0);
	request.rpr_pattern[0] = 0;

	datael_finish_reset(dp);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		DOOR_ERRORS_BLOCK(r);
	}
	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(proto_error(response.rpr_response)));
	}
	iter->iter_sequence++;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (SCF_SUCCESS);
}

static int
datael_setup_iter_pgtyped(scf_iter_t *iter, const scf_datael_t *dp,
    const char *pgtype, boolean_t composed)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_iter_start request;
	struct rep_protocol_response response;

	ssize_t r;

	if (h != iter->iter_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (pgtype == NULL || strlcpy(request.rpr_pattern, pgtype,
	    sizeof (request.rpr_pattern)) >= sizeof (request.rpr_pattern)) {
		scf_iter_reset(iter);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ITER_START;
	request.rpr_iterid = iter->iter_id;
	request.rpr_entity = dp->rd_entity;
	request.rpr_itertype = REP_PROTOCOL_ENTITY_PROPERTYGRP;
	request.rpr_flags = RP_ITER_START_PGTYPE |
	    (composed ? RP_ITER_START_COMPOSED : 0);

	datael_finish_reset(dp);
	scf_iter_reset_locked(iter);
	iter->iter_type = REP_PROTOCOL_ENTITY_PROPERTYGRP;

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);

		DOOR_ERRORS_BLOCK(r);
	}
	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(proto_error(response.rpr_response)));
	}
	iter->iter_sequence++;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (SCF_SUCCESS);
}

static int
datael_iter_next(scf_iter_t *iter, scf_datael_t *out)
{
	scf_handle_t *h = iter->iter_handle;

	struct rep_protocol_iter_read request;
	struct rep_protocol_response response;
	ssize_t r;

	if (h != out->rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	if (iter->iter_type == REP_PROTOCOL_ENTITY_NONE ||
	    iter->iter_sequence == 1) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_NOT_SET));
	}

	if (out->rd_type != iter->iter_type) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	request.rpr_request = REP_PROTOCOL_ITER_READ;
	request.rpr_iterid = iter->iter_id;
	request.rpr_sequence = iter->iter_sequence;
	request.rpr_entityid = out->rd_entity;

	datael_finish_reset(out);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		DOOR_ERRORS_BLOCK(r);
	}

	if (response.rpr_response == REP_PROTOCOL_DONE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (0);
	}
	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(proto_error(response.rpr_response)));
	}
	iter->iter_sequence++;
	(void) pthread_mutex_unlock(&h->rh_lock);

	return (1);
}

int
scf_iter_scope_services(scf_iter_t *iter, const scf_scope_t *s)
{
	return (datael_setup_iter(iter, &s->rd_d,
	    REP_PROTOCOL_ENTITY_SERVICE, 0));
}

int
scf_iter_next_service(scf_iter_t *iter, scf_service_t *out)
{
	return (datael_iter_next(iter, &out->rd_d));
}

int
scf_iter_service_instances(scf_iter_t *iter, const scf_service_t *svc)
{
	return (datael_setup_iter(iter, &svc->rd_d,
	    REP_PROTOCOL_ENTITY_INSTANCE, 0));
}

int
scf_iter_next_instance(scf_iter_t *iter, scf_instance_t *out)
{
	return (datael_iter_next(iter, &out->rd_d));
}

int
scf_iter_service_pgs(scf_iter_t *iter, const scf_service_t *svc)
{
	return (datael_setup_iter(iter, &svc->rd_d,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, 0));
}

int
scf_iter_service_pgs_typed(scf_iter_t *iter, const scf_service_t *svc,
    const char *type)
{
	return (datael_setup_iter_pgtyped(iter, &svc->rd_d, type, 0));
}

int
scf_iter_instance_snapshots(scf_iter_t *iter, const scf_instance_t *inst)
{
	return (datael_setup_iter(iter, &inst->rd_d,
	    REP_PROTOCOL_ENTITY_SNAPSHOT, 0));
}

int
scf_iter_next_snapshot(scf_iter_t *iter, scf_snapshot_t *out)
{
	return (datael_iter_next(iter, &out->rd_d));
}

int
scf_iter_instance_pgs(scf_iter_t *iter, const scf_instance_t *inst)
{
	return (datael_setup_iter(iter, &inst->rd_d,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, 0));
}

int
scf_iter_instance_pgs_typed(scf_iter_t *iter, const scf_instance_t *inst,
    const char *type)
{
	return (datael_setup_iter_pgtyped(iter, &inst->rd_d, type, 0));
}

int
scf_iter_instance_pgs_composed(scf_iter_t *iter, const scf_instance_t *inst,
    const scf_snapshot_t *snap)
{
	if (snap != NULL && inst->rd_d.rd_handle != snap->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	return (datael_setup_iter(iter, snap ? &snap->rd_d : &inst->rd_d,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, 1));
}

int
scf_iter_instance_pgs_typed_composed(scf_iter_t *iter,
    const scf_instance_t *inst, const scf_snapshot_t *snap, const char *type)
{
	if (snap != NULL && inst->rd_d.rd_handle != snap->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	return (datael_setup_iter_pgtyped(iter,
	    snap ? &snap->rd_d : &inst->rd_d, type, 1));
}

int
scf_iter_snaplevel_pgs(scf_iter_t *iter, const scf_snaplevel_t *inst)
{
	return (datael_setup_iter(iter, &inst->rd_d,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, 0));
}

int
scf_iter_snaplevel_pgs_typed(scf_iter_t *iter, const scf_snaplevel_t *inst,
    const char *type)
{
	return (datael_setup_iter_pgtyped(iter, &inst->rd_d, type, 0));
}

int
scf_iter_next_pg(scf_iter_t *iter, scf_propertygroup_t *out)
{
	return (datael_iter_next(iter, &out->rd_d));
}

int
scf_iter_pg_properties(scf_iter_t *iter, const scf_propertygroup_t *pg)
{
	return (datael_setup_iter(iter, &pg->rd_d,
	    REP_PROTOCOL_ENTITY_PROPERTY, 0));
}

int
scf_iter_next_property(scf_iter_t *iter, scf_property_t *out)
{
	return (datael_iter_next(iter, &out->rd_d));
}

/*
 * Fails with
 *   _INVALID_ARGUMENT - handle is NULL
 *   _INTERNAL - server response too big
 *		 entity already set up with different type
 *   _NO_RESOURCES
 *   _NO_MEMORY
 */
scf_scope_t *
scf_scope_create(scf_handle_t *handle)
{
	scf_scope_t *ret;

	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_SCOPE) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

scf_handle_t *
scf_scope_handle(const scf_scope_t *val)
{
	return (datael_handle(&val->rd_d));
}

void
scf_scope_destroy(scf_scope_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

ssize_t
scf_scope_get_name(const scf_scope_t *rep, char *out, size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len, RP_ENTITY_NAME_NAME));
}

/*ARGSUSED*/
int
scf_scope_get_parent(const scf_scope_t *child, scf_scope_t *parent)
{
	char name[1];

	/* fake up the side-effects */
	datael_reset(&parent->rd_d);
	if (scf_scope_get_name(child, name, sizeof (name)) < 0)
		return (-1);
	return (scf_set_error(SCF_ERROR_NOT_FOUND));
}

/*
 * Fails with _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED, _INTERNAL
 * (bad server response or id in use), _NO_RESOURCES, or _NO_MEMORY.
 */
scf_service_t *
scf_service_create(scf_handle_t *handle)
{
	scf_service_t *ret;
	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_SERVICE) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}


/*
 * Fails with
 *   _HANDLE_MISMATCH
 *   _INVALID_ARGUMENT
 *   _NOT_BOUND
 *   _CONNECTION_BROKEN
 *   _INTERNAL
 *   _EXISTS
 *   _DELETED
 *   _NOT_SET
 *   _NO_RESOURCES
 *   _PERMISSION_DENIED
 *   _BACKEND_ACCESS
 *   _BACKEND_READONLY
 */
int
scf_scope_add_service(const scf_scope_t *scope, const char *name,
    scf_service_t *svc)
{
	return (datael_add_child(&scope->rd_d, name,
	    REP_PROTOCOL_ENTITY_SERVICE, (svc != NULL)? &svc->rd_d : NULL));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_scope_get_service(const scf_scope_t *s, const char *name,
    scf_service_t *svc)
{
	return (datael_get_child(&s->rd_d, name, REP_PROTOCOL_ENTITY_SERVICE,
	    svc ? &svc->rd_d : NULL, 0));
}

scf_handle_t *
scf_service_handle(const scf_service_t *val)
{
	return (datael_handle(&val->rd_d));
}

int
scf_service_delete(scf_service_t *svc)
{
	return (datael_delete(&svc->rd_d));
}

int
scf_instance_delete(scf_instance_t *inst)
{
	return (datael_delete(&inst->rd_d));
}

int
scf_pg_delete(scf_propertygroup_t *pg)
{
	return (datael_delete(&pg->rd_d));
}

int
_scf_snapshot_delete(scf_snapshot_t *snap)
{
	return (datael_delete(&snap->rd_d));
}

/*
 * Fails with
 *   _HANDLE_MISMATCH
 *   _INVALID_ARGUMENT
 *   _NOT_BOUND
 *   _CONNECTION_BROKEN
 *   _INTERNAL
 *   _EXISTS
 *   _DELETED
 *   _NOT_SET
 *   _NO_RESOURCES
 *   _PERMISSION_DENIED
 *   _BACKEND_ACCESS
 *   _BACKEND_READONLY
 */
int
scf_service_add_instance(const scf_service_t *svc, const char *name,
    scf_instance_t *instance)
{
	return (datael_add_child(&svc->rd_d, name,
	    REP_PROTOCOL_ENTITY_INSTANCE,
	    (instance != NULL)? &instance->rd_d : NULL));
}


/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_service_get_instance(const scf_service_t *svc, const char *name,
    scf_instance_t *inst)
{
	return (datael_get_child(&svc->rd_d, name, REP_PROTOCOL_ENTITY_INSTANCE,
	    inst ? &inst->rd_d : NULL, 0));
}

int
scf_service_add_pg(const scf_service_t *svc, const char *name,
    const char *type, uint32_t flags, scf_propertygroup_t *pg)
{
	return (datael_add_pg(&svc->rd_d, name, type, flags,
	    (pg != NULL)?&pg->rd_d : NULL));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_service_get_pg(const scf_service_t *svc, const char *name,
    scf_propertygroup_t *pg)
{
	return (datael_get_child(&svc->rd_d, name,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, pg ? &pg->rd_d : NULL, 0));
}

int
scf_instance_add_pg(const scf_instance_t *inst, const char *name,
    const char *type, uint32_t flags, scf_propertygroup_t *pg)
{
	return (datael_add_pg(&inst->rd_d, name, type, flags,
	    (pg != NULL)?&pg->rd_d : NULL));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_instance_get_snapshot(const scf_instance_t *inst, const char *name,
    scf_snapshot_t *pg)
{
	return (datael_get_child(&inst->rd_d, name,
	    REP_PROTOCOL_ENTITY_SNAPSHOT, pg ? &pg->rd_d : NULL, 0));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_instance_get_pg(const scf_instance_t *inst, const char *name,
    scf_propertygroup_t *pg)
{
	return (datael_get_child(&inst->rd_d, name,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, pg ? &pg->rd_d : NULL, 0));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_instance_get_pg_composed(const scf_instance_t *inst,
    const scf_snapshot_t *snap, const char *name, scf_propertygroup_t *pg)
{
	if (snap != NULL && inst->rd_d.rd_handle != snap->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	return (datael_get_child(snap ? &snap->rd_d : &inst->rd_d, name,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, pg ? &pg->rd_d : NULL, 1));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_pg_get_property(const scf_propertygroup_t *pg, const char *name,
    scf_property_t *prop)
{
	return (datael_get_child(&pg->rd_d, name, REP_PROTOCOL_ENTITY_PROPERTY,
	    prop ? &prop->rd_d : NULL, 0));
}

void
scf_service_destroy(scf_service_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

ssize_t
scf_service_get_name(const scf_service_t *rep, char *out, size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len, RP_ENTITY_NAME_NAME));
}

/*
 * Fails with _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED, _INTERNAL
 * (bad server response or id in use), _NO_RESOURCES, or _NO_MEMORY.
 */
scf_instance_t *
scf_instance_create(scf_handle_t *handle)
{
	scf_instance_t *ret;

	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_INSTANCE) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

scf_handle_t *
scf_instance_handle(const scf_instance_t *val)
{
	return (datael_handle(&val->rd_d));
}

void
scf_instance_destroy(scf_instance_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

ssize_t
scf_instance_get_name(const scf_instance_t *rep, char *out, size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len, RP_ENTITY_NAME_NAME));
}

/*
 * Fails with _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED, _INTERNAL
 * (bad server response or id in use), _NO_RESOURCES, or _NO_MEMORY.
 */
scf_snapshot_t *
scf_snapshot_create(scf_handle_t *handle)
{
	scf_snapshot_t *ret;

	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_SNAPSHOT) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

scf_handle_t *
scf_snapshot_handle(const scf_snapshot_t *val)
{
	return (datael_handle(&val->rd_d));
}

void
scf_snapshot_destroy(scf_snapshot_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

ssize_t
scf_snapshot_get_name(const scf_snapshot_t *rep, char *out, size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len, RP_ENTITY_NAME_NAME));
}

/*
 * Fails with _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED, _INTERNAL
 * (bad server response or id in use), _NO_RESOURCES, _NO_MEMORY.
 */
scf_snaplevel_t *
scf_snaplevel_create(scf_handle_t *handle)
{
	scf_snaplevel_t *ret;

	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_SNAPLEVEL) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

scf_handle_t *
scf_snaplevel_handle(const scf_snaplevel_t *val)
{
	return (datael_handle(&val->rd_d));
}

void
scf_snaplevel_destroy(scf_snaplevel_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

ssize_t
scf_snaplevel_get_scope_name(const scf_snaplevel_t *rep, char *out, size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len,
	    RP_ENTITY_NAME_SNAPLEVEL_SCOPE));
}

ssize_t
scf_snaplevel_get_service_name(const scf_snaplevel_t *rep, char *out,
    size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len,
	    RP_ENTITY_NAME_SNAPLEVEL_SERVICE));
}

ssize_t
scf_snaplevel_get_instance_name(const scf_snaplevel_t *rep, char *out,
    size_t len)
{
	return (datael_get_name(&rep->rd_d, out, len,
	    RP_ENTITY_NAME_SNAPLEVEL_INSTANCE));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _NOT_FOUND.
 */
int
scf_snaplevel_get_pg(const scf_snaplevel_t *snap, const char *name,
    scf_propertygroup_t *pg)
{
	return (datael_get_child(&snap->rd_d, name,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP, pg ? &pg->rd_d : NULL, 0));
}

static int
snaplevel_next(const scf_datael_t *src, scf_snaplevel_t *dst_arg)
{
	scf_handle_t *h = src->rd_handle;
	scf_snaplevel_t *dst = dst_arg;
	struct rep_protocol_entity_pair request;
	struct rep_protocol_response response;
	int r;
	int dups = 0;

	if (h != dst->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (src == &dst->rd_d) {
		dups = 1;
		dst = HANDLE_HOLD_SNAPLVL(h);
	}
	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_NEXT_SNAPLEVEL;
	request.rpr_entity_src = src->rd_entity;
	request.rpr_entity_dst = dst->rd_d.rd_entity;

	datael_finish_reset(src);
	datael_finish_reset(&dst->rd_d);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	/*
	 * if we succeeded, we need to swap dst and dst_arg's identity.  We
	 * take advantage of the fact that the only in-library knowledge is
	 * their entity ids.
	 */
	if (dups && r >= 0 &&
	    (response.rpr_response == REP_PROTOCOL_SUCCESS ||
	    response.rpr_response == REP_PROTOCOL_DONE)) {
		int entity = dst->rd_d.rd_entity;

		dst->rd_d.rd_entity = dst_arg->rd_d.rd_entity;
		dst_arg->rd_d.rd_entity = entity;
	}
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (dups)
		HANDLE_RELE_SNAPLVL(h);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS &&
	    response.rpr_response != REP_PROTOCOL_DONE) {
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	return (response.rpr_response == REP_PROTOCOL_SUCCESS) ?
	    SCF_SUCCESS : SCF_COMPLETE;
}

int scf_snapshot_get_base_snaplevel(const scf_snapshot_t *base,
    scf_snaplevel_t *out)
{
	return (snaplevel_next(&base->rd_d, out));
}

int scf_snaplevel_get_next_snaplevel(const scf_snaplevel_t *base,
    scf_snaplevel_t *out)
{
	return (snaplevel_next(&base->rd_d, out));
}

/*
 * Fails with _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED, _INTERNAL
 * (bad server response or id in use), _NO_RESOURCES, or _NO_MEMORY.
 */
scf_propertygroup_t *
scf_pg_create(scf_handle_t *handle)
{
	scf_propertygroup_t *ret;
	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_PROPERTYGRP) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

scf_handle_t *
scf_pg_handle(const scf_propertygroup_t *val)
{
	return (datael_handle(&val->rd_d));
}

void
scf_pg_destroy(scf_propertygroup_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

ssize_t
scf_pg_get_name(const scf_propertygroup_t *pg,  char *out, size_t len)
{
	return (datael_get_name(&pg->rd_d, out, len, RP_ENTITY_NAME_NAME));
}

ssize_t
scf_pg_get_type(const scf_propertygroup_t *pg,  char *out, size_t len)
{
	return (datael_get_name(&pg->rd_d, out, len, RP_ENTITY_NAME_PGTYPE));
}

int
scf_pg_get_flags(const scf_propertygroup_t *pg, uint32_t *out)
{
	char buf[REP_PROTOCOL_NAME_LEN];
	ssize_t res;

	res = datael_get_name(&pg->rd_d, buf, sizeof (buf),
	    RP_ENTITY_NAME_PGFLAGS);

	if (res == -1)
		return (-1);

	if (uu_strtouint(buf, out, sizeof (*out), 0, 0, UINT32_MAX) == -1)
		return (scf_set_error(SCF_ERROR_INTERNAL));

	return (0);
}

static int
datael_update(scf_datael_t *dp)
{
	scf_handle_t *h = dp->rd_handle;

	struct rep_protocol_entity_update request;
	struct rep_protocol_response response;

	int r;

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ENTITY_UPDATE;
	request.rpr_entityid = dp->rd_entity;

	datael_finish_reset(dp);
	request.rpr_changeid = handle_next_changeid(h);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	/*
	 * This should never happen but if it does something has
	 * gone terribly wrong and we should abort.
	 */
	if (response.rpr_response == REP_PROTOCOL_FAIL_BAD_REQUEST)
		abort();

	if (response.rpr_response != REP_PROTOCOL_SUCCESS &&
	    response.rpr_response != REP_PROTOCOL_DONE) {
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	return (response.rpr_response == REP_PROTOCOL_SUCCESS) ?
	    SCF_SUCCESS : SCF_COMPLETE;
}

int
scf_pg_update(scf_propertygroup_t *pg)
{
	return (datael_update(&pg->rd_d));
}

int
scf_snapshot_update(scf_snapshot_t *snap)
{
	return (datael_update(&snap->rd_d));
}

int
_scf_pg_wait(scf_propertygroup_t *pg, int timeout)
{
	scf_handle_t *h = pg->rd_d.rd_handle;

	struct rep_protocol_propertygrp_request request;
	struct rep_protocol_response response;

	struct pollfd pollfd;

	int r;

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_PROPERTYGRP_SETUP_WAIT;
	request.rpr_entityid = pg->rd_d.rd_entity;

	datael_finish_reset(&pg->rd_d);
	if (!handle_is_bound(h)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_CONNECTION_BROKEN));
	}
	r = make_door_call_retfd(h->rh_doorfd, &request, sizeof (request),
	    &response, sizeof (response), &pollfd.fd);
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	assert((response.rpr_response == REP_PROTOCOL_SUCCESS) ==
	    (pollfd.fd != -1));

	if (response.rpr_response == REP_PROTOCOL_FAIL_NOT_LATEST)
		return (SCF_SUCCESS);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	pollfd.events = 0;
	pollfd.revents = 0;

	r = poll(&pollfd, 1, timeout * MILLISEC);

	(void) close(pollfd.fd);
	return (pollfd.revents ? SCF_SUCCESS : SCF_COMPLETE);
}

static int
scf_notify_add_pattern(scf_handle_t *h, int type, const char *name)
{
	struct rep_protocol_notify_request request;
	struct rep_protocol_response response;
	int r;

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_CLIENT_ADD_NOTIFY;
	request.rpr_type = type;
	(void) strlcpy(request.rpr_pattern, name, sizeof (request.rpr_pattern));

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

int
_scf_notify_add_pgname(scf_handle_t *h, const char *name)
{
	return (scf_notify_add_pattern(h, REP_PROTOCOL_NOTIFY_PGNAME, name));
}

int
_scf_notify_add_pgtype(scf_handle_t *h, const char *type)
{
	return (scf_notify_add_pattern(h, REP_PROTOCOL_NOTIFY_PGTYPE, type));
}

int
_scf_notify_wait(scf_propertygroup_t *pg, char *out, size_t sz)
{
	struct rep_protocol_wait_request request;
	struct rep_protocol_fmri_response response;

	scf_handle_t *h = pg->rd_d.rd_handle;
	int dummy;
	int fd;
	int r;

	(void) pthread_mutex_lock(&h->rh_lock);
	datael_finish_reset(&pg->rd_d);
	if (!handle_is_bound(h)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_CONNECTION_BROKEN));
	}
	fd = h->rh_doorfd;
	++h->rh_fd_users;
	assert(h->rh_fd_users > 0);

	request.rpr_request = REP_PROTOCOL_CLIENT_WAIT;
	request.rpr_entityid = pg->rd_d.rd_entity;
	(void) pthread_mutex_unlock(&h->rh_lock);

	r = make_door_call_retfd(fd, &request, sizeof (request),
	    &response, sizeof (response), &dummy);

	(void) pthread_mutex_lock(&h->rh_lock);
	assert(h->rh_fd_users > 0);
	if (--h->rh_fd_users == 0) {
		(void) pthread_cond_broadcast(&h->rh_cv);
		/*
		 * check for a delayed close, now that there are no other
		 * users.
		 */
		if (h->rh_doorfd_old != -1) {
			assert(h->rh_doorfd == -1);
			assert(fd == h->rh_doorfd_old);
			(void) close(h->rh_doorfd_old);
			h->rh_doorfd_old = -1;
		}
	}
	handle_unrefed(h);			/* drops h->rh_lock */

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response == REP_PROTOCOL_DONE)
		return (scf_set_error(SCF_ERROR_NOT_SET));

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	/* the following will be non-zero for delete notifications */
	return (strlcpy(out, response.rpr_fmri, sz));
}

static int
_scf_snapshot_take(scf_instance_t *inst, const char *name,
    scf_snapshot_t *snap, int flags)
{
	scf_handle_t *h = inst->rd_d.rd_handle;

	struct rep_protocol_snapshot_take request;
	struct rep_protocol_response response;

	int r;

	if (h != snap->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (strlcpy(request.rpr_name, (name != NULL)? name : "",
	    sizeof (request.rpr_name)) >= sizeof (request.rpr_name))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_SNAPSHOT_TAKE;
	request.rpr_entityid_src = inst->rd_d.rd_entity;
	request.rpr_entityid_dest = snap->rd_d.rd_entity;
	request.rpr_flags = flags;

	datael_finish_reset(&inst->rd_d);
	datael_finish_reset(&snap->rd_d);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

int
_scf_snapshot_take_new_named(scf_instance_t *inst,
    const char *svcname, const char *instname, const char *snapname,
    scf_snapshot_t *snap)
{
	scf_handle_t *h = inst->rd_d.rd_handle;

	struct rep_protocol_snapshot_take_named request;
	struct rep_protocol_response response;

	int r;

	if (h != snap->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (strlcpy(request.rpr_svcname, svcname,
	    sizeof (request.rpr_svcname)) >= sizeof (request.rpr_svcname))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	if (strlcpy(request.rpr_instname, instname,
	    sizeof (request.rpr_instname)) >= sizeof (request.rpr_instname))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	if (strlcpy(request.rpr_name, snapname,
	    sizeof (request.rpr_name)) >= sizeof (request.rpr_name))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_SNAPSHOT_TAKE_NAMED;
	request.rpr_entityid_src = inst->rd_d.rd_entity;
	request.rpr_entityid_dest = snap->rd_d.rd_entity;

	datael_finish_reset(&inst->rd_d);
	datael_finish_reset(&snap->rd_d);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		assert(response.rpr_response !=
		    REP_PROTOCOL_FAIL_TYPE_MISMATCH);
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	return (SCF_SUCCESS);
}

int
_scf_snapshot_take_new(scf_instance_t *inst, const char *name,
    scf_snapshot_t *snap)
{
	return (_scf_snapshot_take(inst, name, snap, REP_SNAPSHOT_NEW));
}

int
_scf_snapshot_take_attach(scf_instance_t *inst, scf_snapshot_t *snap)
{
	return (_scf_snapshot_take(inst, NULL, snap, REP_SNAPSHOT_ATTACH));
}

int
_scf_snapshot_attach(scf_snapshot_t *src, scf_snapshot_t *dest)
{
	scf_handle_t *h = dest->rd_d.rd_handle;

	struct rep_protocol_snapshot_attach request;
	struct rep_protocol_response response;

	int r;

	if (h != src->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_SNAPSHOT_ATTACH;
	request.rpr_entityid_src = src->rd_d.rd_entity;
	request.rpr_entityid_dest = dest->rd_d.rd_entity;

	datael_finish_reset(&src->rd_d);
	datael_finish_reset(&dest->rd_d);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

/*
 * Fails with _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED, _INTERNAL
 * (bad server response or id in use), _NO_RESOURCES, or _NO_MEMORY.
 */
scf_property_t *
scf_property_create(scf_handle_t *handle)
{
	scf_property_t *ret;
	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		if (datael_init(&ret->rd_d, handle,
		    REP_PROTOCOL_ENTITY_PROPERTY) == -1) {
			uu_free(ret);
			return (NULL);
		}
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

scf_handle_t *
scf_property_handle(const scf_property_t *val)
{
	return (datael_handle(&val->rd_d));
}

void
scf_property_destroy(scf_property_t *val)
{
	if (val == NULL)
		return;

	datael_destroy(&val->rd_d);
	uu_free(val);
}

static int
property_type_locked(const scf_property_t *prop,
    rep_protocol_value_type_t *out)
{
	scf_handle_t *h = prop->rd_d.rd_handle;

	struct rep_protocol_property_request request;
	struct rep_protocol_integer_response response;

	int r;

	assert(MUTEX_HELD(&h->rh_lock));

	request.rpr_request = REP_PROTOCOL_PROPERTY_GET_TYPE;
	request.rpr_entityid = prop->rd_d.rd_entity;

	datael_finish_reset(&prop->rd_d);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS ||
	    r < sizeof (response)) {
		return (scf_set_error(proto_error(response.rpr_response)));
	}
	*out = response.rpr_value;
	return (SCF_SUCCESS);
}

int
scf_property_type(const scf_property_t *prop, scf_type_t *out)
{
	scf_handle_t *h = prop->rd_d.rd_handle;
	rep_protocol_value_type_t out_raw;
	int ret;

	(void) pthread_mutex_lock(&h->rh_lock);
	ret = property_type_locked(prop, &out_raw);
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (ret == SCF_SUCCESS)
		*out = scf_protocol_type_to_type(out_raw);

	return (ret);
}

int
scf_property_is_type(const scf_property_t *prop, scf_type_t base_arg)
{
	scf_handle_t *h = prop->rd_d.rd_handle;
	rep_protocol_value_type_t base = scf_type_to_protocol_type(base_arg);
	rep_protocol_value_type_t type;
	int ret;

	if (base == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	(void) pthread_mutex_lock(&h->rh_lock);
	ret = property_type_locked(prop, &type);
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (ret == SCF_SUCCESS) {
		if (!scf_is_compatible_protocol_type(base, type))
			return (scf_set_error(SCF_ERROR_TYPE_MISMATCH));
	}
	return (ret);
}

int
scf_is_compatible_type(scf_type_t base_arg, scf_type_t type_arg)
{
	rep_protocol_value_type_t base = scf_type_to_protocol_type(base_arg);
	rep_protocol_value_type_t type = scf_type_to_protocol_type(type_arg);

	if (base == REP_PROTOCOL_TYPE_INVALID ||
	    type == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	if (!scf_is_compatible_protocol_type(base, type))
		return (scf_set_error(SCF_ERROR_TYPE_MISMATCH));

	return (SCF_SUCCESS);
}

ssize_t
scf_property_get_name(const scf_property_t *prop, char *out, size_t len)
{
	return (datael_get_name(&prop->rd_d, out, len, RP_ENTITY_NAME_NAME));
}

/*
 * transaction functions
 */

/*
 * Fails with _NO_MEMORY, _INVALID_ARGUMENT (handle is NULL), _HANDLE_DESTROYED,
 * _INTERNAL (bad server response or id in use), or _NO_RESOURCES.
 */
scf_transaction_t *
scf_transaction_create(scf_handle_t *handle)
{
	scf_transaction_t *ret;

	ret = uu_zalloc(sizeof (scf_transaction_t));
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}
	if (datael_init(&ret->tran_pg.rd_d, handle,
	    REP_PROTOCOL_ENTITY_PROPERTYGRP) == -1) {
		uu_free(ret);
		return (NULL);			/* error already set */
	}
	ret->tran_state = TRAN_STATE_NEW;
	ret->tran_props = uu_list_create(tran_entry_pool, ret, UU_LIST_SORTED);
	if (ret->tran_props == NULL) {
		datael_destroy(&ret->tran_pg.rd_d);
		uu_free(ret);
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}

	return (ret);
}

scf_handle_t *
scf_transaction_handle(const scf_transaction_t *val)
{
	return (handle_get(val->tran_pg.rd_d.rd_handle));
}

int
scf_transaction_start(scf_transaction_t *tran, scf_propertygroup_t *pg)
{
	scf_handle_t *h = tran->tran_pg.rd_d.rd_handle;

	struct rep_protocol_transaction_start request;
	struct rep_protocol_response response;
	int r;

	if (h != pg->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);
	if (tran->tran_state != TRAN_STATE_NEW) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_IN_USE));
	}
	request.rpr_request = REP_PROTOCOL_PROPERTYGRP_TX_START;
	request.rpr_entityid_tx = tran->tran_pg.rd_d.rd_entity;
	request.rpr_entityid = pg->rd_d.rd_entity;

	datael_finish_reset(&tran->tran_pg.rd_d);
	datael_finish_reset(&pg->rd_d);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		DOOR_ERRORS_BLOCK(r);
	}

	/* r < sizeof (response) cannot happen because sizeof (response) == 4 */

	if (response.rpr_response != REP_PROTOCOL_SUCCESS ||
	    r < sizeof (response)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	tran->tran_state = TRAN_STATE_SETUP;
	tran->tran_invalid = 0;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (SCF_SUCCESS);
}

static void
entry_invalidate(scf_transaction_entry_t *cur, int and_destroy,
    int and_reset_value)
{
	scf_value_t *v, *next;
	scf_transaction_t *tx;
	scf_handle_t *h = cur->entry_handle;

	assert(MUTEX_HELD(&h->rh_lock));

	if ((tx = cur->entry_tx) != NULL) {
		tx->tran_invalid = 1;
		uu_list_remove(tx->tran_props, cur);
		cur->entry_tx = NULL;
	}

	cur->entry_property = NULL;
	cur->entry_state = ENTRY_STATE_INVALID;
	cur->entry_action = REP_PROTOCOL_TX_ENTRY_INVALID;
	cur->entry_type = REP_PROTOCOL_TYPE_INVALID;

	for (v = cur->entry_head; v != NULL; v = next) {
		next = v->value_next;
		v->value_tx = NULL;
		v->value_next = NULL;
		if (and_destroy || and_reset_value)
			scf_value_reset_locked(v, and_destroy);
	}
	cur->entry_head = NULL;
	cur->entry_tail = NULL;
}

static void
entry_destroy_locked(scf_transaction_entry_t *entry)
{
	scf_handle_t *h = entry->entry_handle;

	assert(MUTEX_HELD(&h->rh_lock));

	entry_invalidate(entry, 0, 0);

	entry->entry_handle = NULL;
	assert(h->rh_entries > 0);
	--h->rh_entries;
	--h->rh_extrefs;
	uu_list_node_fini(entry, &entry->entry_link, tran_entry_pool);
	uu_free(entry);
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _IN_USE, _NOT_FOUND, _EXISTS, _TYPE_MISMATCH.
 */
static int
transaction_add(scf_transaction_t *tran, scf_transaction_entry_t *entry,
    enum rep_protocol_transaction_action action,
    const char *prop, rep_protocol_value_type_t type)
{
	scf_handle_t *h = tran->tran_pg.rd_d.rd_handle;
	scf_transaction_entry_t *old;
	scf_property_t *prop_p;
	rep_protocol_value_type_t oldtype;
	scf_error_t error = SCF_ERROR_NONE;
	int ret;
	uu_list_index_t idx;

	if (h != entry->entry_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (action == REP_PROTOCOL_TX_ENTRY_DELETE)
		assert(type == REP_PROTOCOL_TYPE_INVALID);
	else if (type == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	prop_p = HANDLE_HOLD_PROPERTY(h);

	(void) pthread_mutex_lock(&h->rh_lock);
	if (tran->tran_state != TRAN_STATE_SETUP) {
		error = SCF_ERROR_NOT_SET;
		goto error;
	}
	if (tran->tran_invalid) {
		error = SCF_ERROR_NOT_SET;
		goto error;
	}

	if (entry->entry_state != ENTRY_STATE_INVALID)
		entry_invalidate(entry, 0, 0);

	old = uu_list_find(tran->tran_props, &prop, NULL, &idx);
	if (old != NULL) {
		error = SCF_ERROR_IN_USE;
		goto error;
	}

	ret = datael_get_child_locked(&tran->tran_pg.rd_d, prop,
	    REP_PROTOCOL_ENTITY_PROPERTY, &prop_p->rd_d);
	if (ret == -1 && (error = scf_error()) != SCF_ERROR_NOT_FOUND) {
		goto error;
	}

	switch (action) {
	case REP_PROTOCOL_TX_ENTRY_DELETE:
		if (ret == -1) {
			error = SCF_ERROR_NOT_FOUND;
			goto error;
		}
		break;
	case REP_PROTOCOL_TX_ENTRY_NEW:
		if (ret != -1) {
			error = SCF_ERROR_EXISTS;
			goto error;
		}
		break;

	case REP_PROTOCOL_TX_ENTRY_CLEAR:
	case REP_PROTOCOL_TX_ENTRY_REPLACE:
		if (ret == -1) {
			error = SCF_ERROR_NOT_FOUND;
			goto error;
		}
		if (action == REP_PROTOCOL_TX_ENTRY_CLEAR) {
			if (property_type_locked(prop_p, &oldtype) == -1) {
				error = scf_error();
				goto error;
			}
			if (oldtype != type) {
				error = SCF_ERROR_TYPE_MISMATCH;
				goto error;
			}
		}
		break;
	default:
		assert(0);
		abort();
	}

	(void) strlcpy(entry->entry_namebuf, prop,
	    sizeof (entry->entry_namebuf));
	entry->entry_property = entry->entry_namebuf;
	entry->entry_action = action;
	entry->entry_type = type;

	entry->entry_state = ENTRY_STATE_IN_TX_ACTION;
	entry->entry_tx = tran;
	uu_list_insert(tran->tran_props, entry, idx);

	(void) pthread_mutex_unlock(&h->rh_lock);

	HANDLE_RELE_PROPERTY(h);

	return (SCF_SUCCESS);

error:
	(void) pthread_mutex_unlock(&h->rh_lock);

	HANDLE_RELE_PROPERTY(h);

	return (scf_set_error(error));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _IN_USE, _NOT_FOUND, _EXISTS, _TYPE_MISMATCH.
 */
int
scf_transaction_property_new(scf_transaction_t *tx,
    scf_transaction_entry_t *entry, const char *prop, scf_type_t type)
{
	return (transaction_add(tx, entry, REP_PROTOCOL_TX_ENTRY_NEW,
	    prop, scf_type_to_protocol_type(type)));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _IN_USE, _NOT_FOUND, _EXISTS, _TYPE_MISMATCH.
 */
int
scf_transaction_property_change(scf_transaction_t *tx,
    scf_transaction_entry_t *entry, const char *prop, scf_type_t type)
{
	return (transaction_add(tx, entry, REP_PROTOCOL_TX_ENTRY_CLEAR,
	    prop, scf_type_to_protocol_type(type)));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _IN_USE, _NOT_FOUND, _EXISTS, _TYPE_MISMATCH.
 */
int
scf_transaction_property_change_type(scf_transaction_t *tx,
    scf_transaction_entry_t *entry, const char *prop, scf_type_t type)
{
	return (transaction_add(tx, entry, REP_PROTOCOL_TX_ENTRY_REPLACE,
	    prop, scf_type_to_protocol_type(type)));
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _NOT_BOUND,
 * _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED, _NO_RESOURCES,
 * _BACKEND_ACCESS, _IN_USE, _NOT_FOUND, _EXISTS, _TYPE_MISMATCH.
 */
int
scf_transaction_property_delete(scf_transaction_t *tx,
    scf_transaction_entry_t *entry, const char *prop)
{
	return (transaction_add(tx, entry, REP_PROTOCOL_TX_ENTRY_DELETE,
	    prop, REP_PROTOCOL_TYPE_INVALID));
}

#define	BAD_SIZE (-1UL)

static size_t
commit_value(caddr_t data, scf_value_t *val, rep_protocol_value_type_t t)
{
	size_t len;

	assert(val->value_type == t);

	if (t == REP_PROTOCOL_TYPE_OPAQUE) {
		len = scf_opaque_encode(data, val->value_value,
		    val->value_size);
	} else {
		if (data != NULL)
			len = strlcpy(data, val->value_value,
			    REP_PROTOCOL_VALUE_LEN);
		else
			len = strlen(val->value_value);
		if (len >= REP_PROTOCOL_VALUE_LEN)
			return (BAD_SIZE);
	}
	return (len + 1);	/* count the '\0' */
}

static size_t
commit_process(scf_transaction_entry_t *cur,
    struct rep_protocol_transaction_cmd *out)
{
	scf_value_t *child;
	size_t sz = 0;
	size_t len;
	caddr_t data = (caddr_t)out->rptc_data;
	caddr_t val_data;

	if (out != NULL) {
		len = strlcpy(data, cur->entry_property, REP_PROTOCOL_NAME_LEN);

		out->rptc_action = cur->entry_action;
		out->rptc_type = cur->entry_type;
		out->rptc_name_len = len + 1;
	} else {
		len = strlen(cur->entry_property);
	}

	if (len >= REP_PROTOCOL_NAME_LEN)
		return (BAD_SIZE);

	len = TX_SIZE(len + 1);

	sz += len;
	val_data = data + len;

	for (child = cur->entry_head; child != NULL;
	    child = child->value_next) {
		assert(cur->entry_action != REP_PROTOCOL_TX_ENTRY_DELETE);
		if (out != NULL) {
			len = commit_value(val_data + sizeof (uint32_t), child,
			    cur->entry_type);
			/* LINTED alignment */
			*(uint32_t *)val_data = len;
		} else
			len = commit_value(NULL, child, cur->entry_type);

		if (len == BAD_SIZE)
			return (BAD_SIZE);

		len += sizeof (uint32_t);
		len = TX_SIZE(len);

		sz += len;
		val_data += len;
	}

	assert(val_data - data == sz);

	if (out != NULL)
		out->rptc_size = REP_PROTOCOL_TRANSACTION_CMD_SIZE(sz);

	return (REP_PROTOCOL_TRANSACTION_CMD_SIZE(sz));
}

int
scf_transaction_commit(scf_transaction_t *tran)
{
	scf_handle_t *h = tran->tran_pg.rd_d.rd_handle;

	struct rep_protocol_transaction_commit *request;
	struct rep_protocol_response response;
	uintptr_t cmd;
	scf_transaction_entry_t *cur;
	size_t total, size;
	size_t request_size;
	size_t new_total;
	int r;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (tran->tran_state != TRAN_STATE_SETUP ||
	    tran->tran_invalid) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	total = 0;
	for (cur = uu_list_first(tran->tran_props); cur != NULL;
	    cur = uu_list_next(tran->tran_props, cur)) {
		size = commit_process(cur, NULL);
		if (size == BAD_SIZE) {
			(void) pthread_mutex_unlock(&h->rh_lock);
			return (scf_set_error(SCF_ERROR_INTERNAL));
		}
		assert(TX_SIZE(size) == size);
		total += size;
	}

	request_size = REP_PROTOCOL_TRANSACTION_COMMIT_SIZE(total);
	request = alloca(request_size);
	(void) memset(request, '\0', request_size);
	request->rpr_request = REP_PROTOCOL_PROPERTYGRP_TX_COMMIT;
	request->rpr_entityid = tran->tran_pg.rd_d.rd_entity;
	request->rpr_size = request_size;
	cmd = (uintptr_t)request->rpr_cmd;

	datael_finish_reset(&tran->tran_pg.rd_d);

	new_total = 0;
	for (cur = uu_list_first(tran->tran_props); cur != NULL;
	    cur = uu_list_next(tran->tran_props, cur)) {
		size = commit_process(cur, (void *)cmd);
		if (size == BAD_SIZE) {
			(void) pthread_mutex_unlock(&h->rh_lock);
			return (scf_set_error(SCF_ERROR_INTERNAL));
		}
		cmd += size;
		new_total += size;
	}
	assert(new_total == total);

	r = make_door_call(h, request, request_size,
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		DOOR_ERRORS_BLOCK(r);
	}

	if (response.rpr_response != REP_PROTOCOL_SUCCESS &&
	    response.rpr_response != REP_PROTOCOL_FAIL_NOT_LATEST) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	tran->tran_state = TRAN_STATE_COMMITTED;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (response.rpr_response == REP_PROTOCOL_SUCCESS);
}

static void
transaction_reset(scf_transaction_t *tran)
{
	assert(MUTEX_HELD(&tran->tran_pg.rd_d.rd_handle->rh_lock));

	tran->tran_state = TRAN_STATE_NEW;
	datael_reset_locked(&tran->tran_pg.rd_d);
}

static void
scf_transaction_reset_impl(scf_transaction_t *tran, int and_destroy,
    int and_reset_value)
{
	scf_transaction_entry_t *cur;
	void *cookie;

	(void) pthread_mutex_lock(&tran->tran_pg.rd_d.rd_handle->rh_lock);
	cookie = NULL;
	while ((cur = uu_list_teardown(tran->tran_props, &cookie)) != NULL) {
		cur->entry_tx = NULL;

		assert(cur->entry_state == ENTRY_STATE_IN_TX_ACTION);
		cur->entry_state = ENTRY_STATE_INVALID;

		entry_invalidate(cur, and_destroy, and_reset_value);
		if (and_destroy)
			entry_destroy_locked(cur);
	}
	transaction_reset(tran);
	handle_unrefed(tran->tran_pg.rd_d.rd_handle);
}

void
scf_transaction_reset(scf_transaction_t *tran)
{
	scf_transaction_reset_impl(tran, 0, 0);
}

void
scf_transaction_reset_all(scf_transaction_t *tran)
{
	scf_transaction_reset_impl(tran, 0, 1);
}

void
scf_transaction_destroy(scf_transaction_t *val)
{
	if (val == NULL)
		return;

	scf_transaction_reset(val);

	datael_destroy(&val->tran_pg.rd_d);

	uu_list_destroy(val->tran_props);
	uu_free(val);
}

void
scf_transaction_destroy_children(scf_transaction_t *tran)
{
	if (tran == NULL)
		return;

	scf_transaction_reset_impl(tran, 1, 0);
}

scf_transaction_entry_t *
scf_entry_create(scf_handle_t *h)
{
	scf_transaction_entry_t *ret;

	if (h == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}

	ret = uu_zalloc(sizeof (scf_transaction_entry_t));
	if (ret == NULL) {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
		return (NULL);
	}
	ret->entry_action = REP_PROTOCOL_TX_ENTRY_INVALID;
	ret->entry_handle = h;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (h->rh_flags & HANDLE_DEAD) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		uu_free(ret);
		(void) scf_set_error(SCF_ERROR_HANDLE_DESTROYED);
		return (NULL);
	}
	h->rh_entries++;
	h->rh_extrefs++;
	(void) pthread_mutex_unlock(&h->rh_lock);

	uu_list_node_init(ret, &ret->entry_link, tran_entry_pool);

	return (ret);
}

scf_handle_t *
scf_entry_handle(const scf_transaction_entry_t *val)
{
	return (handle_get(val->entry_handle));
}

void
scf_entry_reset(scf_transaction_entry_t *entry)
{
	scf_handle_t *h = entry->entry_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	entry_invalidate(entry, 0, 0);
	(void) pthread_mutex_unlock(&h->rh_lock);
}

void
scf_entry_destroy_children(scf_transaction_entry_t *entry)
{
	scf_handle_t *h = entry->entry_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	entry_invalidate(entry, 1, 0);
	handle_unrefed(h);			/* drops h->rh_lock */
}

void
scf_entry_destroy(scf_transaction_entry_t *entry)
{
	scf_handle_t *h;

	if (entry == NULL)
		return;

	h = entry->entry_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	entry_destroy_locked(entry);
	handle_unrefed(h);			/* drops h->rh_lock */
}

/*
 * Fails with
 *   _HANDLE_MISMATCH
 *   _NOT_SET - has not been added to a transaction
 *   _INTERNAL - entry is corrupt
 *   _INVALID_ARGUMENT - entry's transaction is not started or corrupt
 *			 entry is set to delete a property
 *			 v is reset or corrupt
 *   _TYPE_MISMATCH - entry & v's types aren't compatible
 *   _IN_USE - v has been added to another entry
 */
int
scf_entry_add_value(scf_transaction_entry_t *entry, scf_value_t *v)
{
	scf_handle_t *h = entry->entry_handle;

	if (h != v->value_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);

	if (entry->entry_state == ENTRY_STATE_INVALID) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_NOT_SET));
	}

	if (entry->entry_state != ENTRY_STATE_IN_TX_ACTION) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INTERNAL));
	}

	if (entry->entry_tx->tran_state != TRAN_STATE_SETUP) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	if (entry->entry_action == REP_PROTOCOL_TX_ENTRY_DELETE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	if (v->value_type == REP_PROTOCOL_TYPE_INVALID) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	if (!scf_is_compatible_protocol_type(entry->entry_type,
	    v->value_type)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_TYPE_MISMATCH));
	}

	if (v->value_tx != NULL) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_IN_USE));
	}

	v->value_tx = entry;
	v->value_next = NULL;
	if (entry->entry_head == NULL) {
		entry->entry_head = v;
		entry->entry_tail = v;
	} else {
		entry->entry_tail->value_next = v;
		entry->entry_tail = v;
	}

	(void) pthread_mutex_unlock(&h->rh_lock);

	return (SCF_SUCCESS);
}

/*
 * value functions
 */
scf_value_t *
scf_value_create(scf_handle_t *h)
{
	scf_value_t *ret;

	if (h == NULL) {
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (NULL);
	}

	ret = uu_zalloc(sizeof (*ret));
	if (ret != NULL) {
		ret->value_type = REP_PROTOCOL_TYPE_INVALID;
		ret->value_handle = h;
		(void) pthread_mutex_lock(&h->rh_lock);
		if (h->rh_flags & HANDLE_DEAD) {
			(void) pthread_mutex_unlock(&h->rh_lock);
			uu_free(ret);
			(void) scf_set_error(SCF_ERROR_HANDLE_DESTROYED);
			return (NULL);
		}
		h->rh_values++;
		h->rh_extrefs++;
		(void) pthread_mutex_unlock(&h->rh_lock);
	} else {
		(void) scf_set_error(SCF_ERROR_NO_MEMORY);
	}

	return (ret);
}

static void
scf_value_reset_locked(scf_value_t *val, int and_destroy)
{
	scf_value_t **curp;
	scf_transaction_entry_t *te;

	scf_handle_t *h = val->value_handle;
	assert(MUTEX_HELD(&h->rh_lock));
	if (val->value_tx != NULL) {
		te = val->value_tx;
		te->entry_tx->tran_invalid = 1;

		val->value_tx = NULL;

		for (curp = &te->entry_head; *curp != NULL;
		    curp = &(*curp)->value_next) {
			if (*curp == val) {
				*curp = val->value_next;
				curp = NULL;
				break;
			}
		}
		assert(curp == NULL);
	}
	val->value_type = REP_PROTOCOL_TYPE_INVALID;

	if (and_destroy) {
		val->value_handle = NULL;
		assert(h->rh_values > 0);
		--h->rh_values;
		--h->rh_extrefs;
		uu_free(val);
	}
}

void
scf_value_reset(scf_value_t *val)
{
	scf_handle_t *h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(val, 0);
	(void) pthread_mutex_unlock(&h->rh_lock);
}

scf_handle_t *
scf_value_handle(const scf_value_t *val)
{
	return (handle_get(val->value_handle));
}

void
scf_value_destroy(scf_value_t *val)
{
	scf_handle_t *h;

	if (val == NULL)
		return;

	h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(val, 1);
	handle_unrefed(h);			/* drops h->rh_lock */
}

scf_type_t
scf_value_base_type(const scf_value_t *val)
{
	rep_protocol_value_type_t t, cur;
	scf_handle_t *h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	t = val->value_type;
	(void) pthread_mutex_unlock(&h->rh_lock);

	for (;;) {
		cur = scf_proto_underlying_type(t);
		if (cur == t)
			break;
		t = cur;
	}

	return (scf_protocol_type_to_type(t));
}

scf_type_t
scf_value_type(const scf_value_t *val)
{
	rep_protocol_value_type_t t;
	scf_handle_t *h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	t = val->value_type;
	(void) pthread_mutex_unlock(&h->rh_lock);

	return (scf_protocol_type_to_type(t));
}

int
scf_value_is_type(const scf_value_t *val, scf_type_t base_arg)
{
	rep_protocol_value_type_t t;
	rep_protocol_value_type_t base = scf_type_to_protocol_type(base_arg);
	scf_handle_t *h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	t = val->value_type;
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (t == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_NOT_SET));
	if (base == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	if (!scf_is_compatible_protocol_type(base, t))
		return (scf_set_error(SCF_ERROR_TYPE_MISMATCH));

	return (SCF_SUCCESS);
}

/*
 * Fails with
 *   _NOT_SET - val is reset
 *   _TYPE_MISMATCH - val's type is not compatible with t
 */
static int
scf_value_check_type(const scf_value_t *val, rep_protocol_value_type_t t)
{
	if (val->value_type == REP_PROTOCOL_TYPE_INVALID) {
		(void) scf_set_error(SCF_ERROR_NOT_SET);
		return (0);
	}
	if (!scf_is_compatible_protocol_type(t, val->value_type)) {
		(void) scf_set_error(SCF_ERROR_TYPE_MISMATCH);
		return (0);
	}
	return (1);
}

/*
 * Fails with
 *   _NOT_SET - val is reset
 *   _TYPE_MISMATCH - val is not _TYPE_BOOLEAN
 */
int
scf_value_get_boolean(const scf_value_t *val, uint8_t *out)
{
	char c;
	scf_handle_t *h = val->value_handle;
	uint8_t o;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(val, REP_PROTOCOL_TYPE_BOOLEAN)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (-1);
	}

	c = val->value_value[0];
	assert((c == '0' || c == '1') && val->value_value[1] == 0);

	o = (c != '0');
	(void) pthread_mutex_unlock(&h->rh_lock);
	if (out != NULL)
		*out = o;
	return (SCF_SUCCESS);
}

int
scf_value_get_count(const scf_value_t *val, uint64_t *out)
{
	scf_handle_t *h = val->value_handle;
	uint64_t o;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(val, REP_PROTOCOL_TYPE_COUNT)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (-1);
	}

	o = strtoull(val->value_value, NULL, 10);
	(void) pthread_mutex_unlock(&h->rh_lock);
	if (out != NULL)
		*out = o;
	return (SCF_SUCCESS);
}

int
scf_value_get_integer(const scf_value_t *val, int64_t *out)
{
	scf_handle_t *h = val->value_handle;
	int64_t o;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(val, REP_PROTOCOL_TYPE_INTEGER)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (-1);
	}

	o = strtoll(val->value_value, NULL, 10);
	(void) pthread_mutex_unlock(&h->rh_lock);
	if (out != NULL)
		*out = o;
	return (SCF_SUCCESS);
}

int
scf_value_get_time(const scf_value_t *val, int64_t *sec_out, int32_t *nsec_out)
{
	scf_handle_t *h = val->value_handle;
	char *p;
	int64_t os;
	int32_t ons;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(val, REP_PROTOCOL_TYPE_TIME)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (-1);
	}

	os = strtoll(val->value_value, &p, 10);
	if (*p == '.')
		ons = strtoul(p + 1, NULL, 10);
	else
		ons = 0;
	(void) pthread_mutex_unlock(&h->rh_lock);
	if (sec_out != NULL)
		*sec_out = os;
	if (nsec_out != NULL)
		*nsec_out = ons;

	return (SCF_SUCCESS);
}

/*
 * Fails with
 *   _NOT_SET - val is reset
 *   _TYPE_MISMATCH - val's type is not compatible with _TYPE_STRING.
 */
ssize_t
scf_value_get_astring(const scf_value_t *val, char *out, size_t len)
{
	ssize_t ret;
	scf_handle_t *h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(val, REP_PROTOCOL_TYPE_STRING)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return ((ssize_t)-1);
	}
	ret = (ssize_t)strlcpy(out, val->value_value, len);
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (ret);
}

ssize_t
scf_value_get_ustring(const scf_value_t *val, char *out, size_t len)
{
	ssize_t ret;
	scf_handle_t *h = val->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(val, REP_PROTOCOL_SUBTYPE_USTRING)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return ((ssize_t)-1);
	}
	ret = (ssize_t)strlcpy(out, val->value_value, len);
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (ret);
}

ssize_t
scf_value_get_opaque(const scf_value_t *v, void *out, size_t len)
{
	ssize_t ret;
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (!scf_value_check_type(v, REP_PROTOCOL_TYPE_OPAQUE)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return ((ssize_t)-1);
	}
	if (len > v->value_size)
		len = v->value_size;
	ret = len;

	(void) memcpy(out, v->value_value, len);
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (ret);
}

void
scf_value_set_boolean(scf_value_t *v, uint8_t new)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	v->value_type = REP_PROTOCOL_TYPE_BOOLEAN;
	(void) sprintf(v->value_value, "%d", (new != 0));
	(void) pthread_mutex_unlock(&h->rh_lock);
}

void
scf_value_set_count(scf_value_t *v, uint64_t new)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	v->value_type = REP_PROTOCOL_TYPE_COUNT;
	(void) sprintf(v->value_value, "%llu", (unsigned long long)new);
	(void) pthread_mutex_unlock(&h->rh_lock);
}

void
scf_value_set_integer(scf_value_t *v, int64_t new)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	v->value_type = REP_PROTOCOL_TYPE_INTEGER;
	(void) sprintf(v->value_value, "%lld", (long long)new);
	(void) pthread_mutex_unlock(&h->rh_lock);
}

int
scf_value_set_time(scf_value_t *v, int64_t new_sec, int32_t new_nsec)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	if (new_nsec < 0 || new_nsec >= NANOSEC) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	v->value_type = REP_PROTOCOL_TYPE_TIME;
	if (new_nsec == 0)
		(void) sprintf(v->value_value, "%lld", (long long)new_sec);
	else
		(void) sprintf(v->value_value, "%lld.%09u", (long long)new_sec,
		    (unsigned)new_nsec);
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (0);
}

int
scf_value_set_astring(scf_value_t *v, const char *new)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	if (!scf_validate_encoded_value(REP_PROTOCOL_TYPE_STRING, new)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	if (strlcpy(v->value_value, new, sizeof (v->value_value)) >=
	    sizeof (v->value_value)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	v->value_type = REP_PROTOCOL_TYPE_STRING;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (0);
}

int
scf_value_set_ustring(scf_value_t *v, const char *new)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	if (!scf_validate_encoded_value(REP_PROTOCOL_SUBTYPE_USTRING, new)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	if (strlcpy(v->value_value, new, sizeof (v->value_value)) >=
	    sizeof (v->value_value)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	v->value_type = REP_PROTOCOL_SUBTYPE_USTRING;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (0);
}

int
scf_value_set_opaque(scf_value_t *v, const void *new, size_t len)
{
	scf_handle_t *h = v->value_handle;

	(void) pthread_mutex_lock(&h->rh_lock);
	scf_value_reset_locked(v, 0);
	if (len > sizeof (v->value_value)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}
	(void) memcpy(v->value_value, new, len);
	v->value_size = len;
	v->value_type = REP_PROTOCOL_TYPE_OPAQUE;
	(void) pthread_mutex_unlock(&h->rh_lock);
	return (0);
}

/*
 * Fails with
 *   _NOT_SET - v_arg is reset
 *   _INTERNAL - v_arg is corrupt
 *
 * If t is not _TYPE_INVALID, fails with
 *   _TYPE_MISMATCH - v_arg's type is not compatible with t
 */
static ssize_t
scf_value_get_as_string_common(const scf_value_t *v_arg,
    rep_protocol_value_type_t t, char *buf, size_t bufsz)
{
	scf_handle_t *h = v_arg->value_handle;
	scf_value_t v_s;
	scf_value_t *v = &v_s;
	ssize_t r;
	uint8_t b;

	(void) pthread_mutex_lock(&h->rh_lock);
	if (t != REP_PROTOCOL_TYPE_INVALID && !scf_value_check_type(v_arg, t)) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (-1);
	}

	v_s = *v_arg;			/* copy locally so we can unlock */
	h->rh_values++;			/* keep the handle from going away */
	h->rh_extrefs++;
	(void) pthread_mutex_unlock(&h->rh_lock);


	switch (REP_PROTOCOL_BASE_TYPE(v->value_type)) {
	case REP_PROTOCOL_TYPE_BOOLEAN:
		r = scf_value_get_boolean(v, &b);
		assert(r == SCF_SUCCESS);

		r = strlcpy(buf, b ? "true" : "false", bufsz);
		break;

	case REP_PROTOCOL_TYPE_COUNT:
	case REP_PROTOCOL_TYPE_INTEGER:
	case REP_PROTOCOL_TYPE_TIME:
	case REP_PROTOCOL_TYPE_STRING:
		r = strlcpy(buf, v->value_value, bufsz);
		break;

	case REP_PROTOCOL_TYPE_OPAQUE:
		/*
		 * Note that we only write out full hex bytes -- if they're
		 * short, and bufsz is even, we'll only fill (bufsz - 2) bytes
		 * with data.
		 */
		if (bufsz > 0)
			(void) scf_opaque_encode(buf, v->value_value,
			    MIN(v->value_size, (bufsz - 1)/2));
		r = (v->value_size * 2);
		break;

	case REP_PROTOCOL_TYPE_INVALID:
		r = scf_set_error(SCF_ERROR_NOT_SET);
		break;

	default:
		r = (scf_set_error(SCF_ERROR_INTERNAL));
		break;
	}

	(void) pthread_mutex_lock(&h->rh_lock);
	h->rh_values--;
	h->rh_extrefs--;
	handle_unrefed(h);

	return (r);
}

ssize_t
scf_value_get_as_string(const scf_value_t *v, char *buf, size_t bufsz)
{
	return (scf_value_get_as_string_common(v, REP_PROTOCOL_TYPE_INVALID,
	    buf, bufsz));
}

ssize_t
scf_value_get_as_string_typed(const scf_value_t *v, scf_type_t type,
    char *buf, size_t bufsz)
{
	rep_protocol_value_type_t ty = scf_type_to_protocol_type(type);
	if (ty == REP_PROTOCOL_TYPE_INVALID)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	return (scf_value_get_as_string_common(v, ty, buf, bufsz));
}

int
scf_value_set_from_string(scf_value_t *v, scf_type_t type, const char *str)
{
	scf_handle_t *h = v->value_handle;
	rep_protocol_value_type_t ty;

	switch (type) {
	case SCF_TYPE_BOOLEAN: {
		uint8_t b;

		if (strcmp(str, "true") == 0 || strcmp(str, "t") == 0 ||
		    strcmp(str, "1") == 0)
			b = 1;
		else if (strcmp(str, "false") == 0 ||
		    strcmp(str, "f") == 0 || strcmp(str, "0") == 0)
			b = 0;
		else {
			goto bad;
		}

		scf_value_set_boolean(v, b);
		return (0);
	}

	case SCF_TYPE_COUNT: {
		uint64_t c;
		char *endp;

		errno = 0;
		c = strtoull(str, &endp, 0);

		if (errno != 0 || endp == str || *endp != '\0')
			goto bad;

		scf_value_set_count(v, c);
		return (0);
	}

	case SCF_TYPE_INTEGER: {
		int64_t i;
		char *endp;

		errno = 0;
		i = strtoll(str, &endp, 0);

		if (errno != 0 || endp == str || *endp != '\0')
			goto bad;

		scf_value_set_integer(v, i);
		return (0);
	}

	case SCF_TYPE_TIME: {
		int64_t s;
		uint32_t ns = 0;
		char *endp, *ns_str;
		size_t len;

		errno = 0;
		s = strtoll(str, &endp, 10);
		if (errno != 0 || endp == str ||
		    (*endp != '\0' && *endp != '.'))
			goto bad;

		if (*endp == '.') {
			ns_str = endp + 1;
			len = strlen(ns_str);
			if (len == 0 || len > 9)
				goto bad;

			ns = strtoul(ns_str, &endp, 10);
			if (errno != 0 || endp == ns_str || *endp != '\0')
				goto bad;

			while (len++ < 9)
				ns *= 10;
			assert(ns < NANOSEC);
		}

		return (scf_value_set_time(v, s, ns));
	}

	case SCF_TYPE_ASTRING:
	case SCF_TYPE_USTRING:
	case SCF_TYPE_OPAQUE:
	case SCF_TYPE_URI:
	case SCF_TYPE_FMRI:
	case SCF_TYPE_HOST:
	case SCF_TYPE_HOSTNAME:
	case SCF_TYPE_NET_ADDR:
	case SCF_TYPE_NET_ADDR_V4:
	case SCF_TYPE_NET_ADDR_V6:
		ty = scf_type_to_protocol_type(type);

		(void) pthread_mutex_lock(&h->rh_lock);
		scf_value_reset_locked(v, 0);
		if (type == SCF_TYPE_OPAQUE) {
			v->value_size = scf_opaque_decode(v->value_value,
			    str, sizeof (v->value_value));
			if (!scf_validate_encoded_value(ty, str)) {
				(void) pthread_mutex_lock(&h->rh_lock);
				goto bad;
			}
		} else {
			(void) strlcpy(v->value_value, str,
			    sizeof (v->value_value));
			if (!scf_validate_encoded_value(ty, v->value_value)) {
				(void) pthread_mutex_lock(&h->rh_lock);
				goto bad;
			}
		}
		v->value_type = ty;
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (SCF_SUCCESS);

	case REP_PROTOCOL_TYPE_INVALID:
	default:
		scf_value_reset(v);
		return (scf_set_error(SCF_ERROR_TYPE_MISMATCH));
	}
bad:
	scf_value_reset(v);
	return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
}

int
scf_iter_property_values(scf_iter_t *iter, const scf_property_t *prop)
{
	return (datael_setup_iter(iter, &prop->rd_d,
	    REP_PROTOCOL_ENTITY_VALUE, 0));
}

int
scf_iter_next_value(scf_iter_t *iter, scf_value_t *v)
{
	scf_handle_t *h = iter->iter_handle;

	struct rep_protocol_iter_read_value request;
	struct rep_protocol_value_response response;

	int r;

	if (h != v->value_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);

	scf_value_reset_locked(v, 0);

	if (iter->iter_type == REP_PROTOCOL_ENTITY_NONE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_NOT_SET));
	}

	if (iter->iter_type != REP_PROTOCOL_ENTITY_VALUE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	request.rpr_request = REP_PROTOCOL_ITER_READ_VALUE;
	request.rpr_iterid = iter->iter_id;
	request.rpr_sequence = iter->iter_sequence;

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		DOOR_ERRORS_BLOCK(r);
	}

	if (response.rpr_response == REP_PROTOCOL_DONE) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (0);
	}
	if (response.rpr_response != REP_PROTOCOL_SUCCESS) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		return (scf_set_error(proto_error(response.rpr_response)));
	}
	iter->iter_sequence++;

	v->value_type = response.rpr_type;

	assert(scf_validate_encoded_value(response.rpr_type,
	    response.rpr_value));

	if (v->value_type != REP_PROTOCOL_TYPE_OPAQUE) {
		(void) strlcpy(v->value_value, response.rpr_value,
		    sizeof (v->value_value));
	} else {
		v->value_size = scf_opaque_decode(v->value_value,
		    response.rpr_value, sizeof (v->value_value));
	}
	(void) pthread_mutex_unlock(&h->rh_lock);

	return (1);
}

int
scf_property_get_value(const scf_property_t *prop, scf_value_t *v)
{
	scf_handle_t *h = prop->rd_d.rd_handle;
	struct rep_protocol_property_request request;
	struct rep_protocol_value_response response;
	int r;

	if (h != v->value_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	(void) pthread_mutex_lock(&h->rh_lock);

	request.rpr_request = REP_PROTOCOL_PROPERTY_GET_VALUE;
	request.rpr_entityid = prop->rd_d.rd_entity;

	scf_value_reset_locked(v, 0);
	datael_finish_reset(&prop->rd_d);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	if (r < 0) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		DOOR_ERRORS_BLOCK(r);
	}

	if (response.rpr_response != REP_PROTOCOL_SUCCESS &&
	    response.rpr_response != REP_PROTOCOL_FAIL_TRUNCATED) {
		(void) pthread_mutex_unlock(&h->rh_lock);
		assert(response.rpr_response !=
		    REP_PROTOCOL_FAIL_TYPE_MISMATCH);
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	v->value_type = response.rpr_type;
	if (v->value_type != REP_PROTOCOL_TYPE_OPAQUE) {
		(void) strlcpy(v->value_value, response.rpr_value,
		    sizeof (v->value_value));
	} else {
		v->value_size = scf_opaque_decode(v->value_value,
		    response.rpr_value, sizeof (v->value_value));
	}
	(void) pthread_mutex_unlock(&h->rh_lock);
	return ((response.rpr_response == REP_PROTOCOL_SUCCESS)?
	    SCF_SUCCESS : scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED));
}

int
scf_pg_get_parent_service(const scf_propertygroup_t *pg, scf_service_t *svc)
{
	return (datael_get_parent(&pg->rd_d, &svc->rd_d));
}

int
scf_pg_get_parent_instance(const scf_propertygroup_t *pg, scf_instance_t *inst)
{
	return (datael_get_parent(&pg->rd_d, &inst->rd_d));
}

int
scf_pg_get_parent_snaplevel(const scf_propertygroup_t *pg,
    scf_snaplevel_t *level)
{
	return (datael_get_parent(&pg->rd_d, &level->rd_d));
}

int
scf_service_get_parent(const scf_service_t *svc, scf_scope_t *s)
{
	return (datael_get_parent(&svc->rd_d, &s->rd_d));
}

int
scf_instance_get_parent(const scf_instance_t *inst, scf_service_t *svc)
{
	return (datael_get_parent(&inst->rd_d, &svc->rd_d));
}

int
scf_snapshot_get_parent(const scf_snapshot_t *inst, scf_instance_t *svc)
{
	return (datael_get_parent(&inst->rd_d, &svc->rd_d));
}

int
scf_snaplevel_get_parent(const scf_snaplevel_t *inst, scf_snapshot_t *svc)
{
	return (datael_get_parent(&inst->rd_d, &svc->rd_d));
}

/*
 * FMRI functions
 *
 * Note: In the scf_parse_svc_fmri(), scf_parse_file_fmri() and
 * scf_parse_fmri(), fmri isn't const because that would require
 * allocating memory. Also, note that scope, at least, is not necessarily
 * in the passed in fmri.
 */

int
scf_parse_svc_fmri(char *fmri, const char **scope, const char **service,
    const char **instance, const char **propertygroup, const char **property)
{
	char *s, *e, *te, *tpg;
	char *my_s = NULL, *my_i = NULL, *my_pg = NULL, *my_p = NULL;

	if (scope != NULL)
		*scope = NULL;
	if (service != NULL)
		*service = NULL;
	if (instance != NULL)
		*instance = NULL;
	if (propertygroup != NULL)
		*propertygroup = NULL;
	if (property != NULL)
		*property = NULL;

	s = fmri;
	e = strchr(s, '\0');

	if (strncmp(s, SCF_FMRI_SVC_PREFIX,
	    sizeof (SCF_FMRI_SVC_PREFIX) - 1) == 0)
		s += sizeof (SCF_FMRI_SVC_PREFIX) - 1;

	if (strncmp(s, SCF_FMRI_SCOPE_PREFIX,
	    sizeof (SCF_FMRI_SCOPE_PREFIX) - 1) == 0) {
		char *my_scope;

		s += sizeof (SCF_FMRI_SCOPE_PREFIX) - 1;
		te = strstr(s, SCF_FMRI_SERVICE_PREFIX);
		if (te == NULL)
			te = e;

		*te = 0;
		my_scope = s;

		s = te;
		if (s < e)
			s += sizeof (SCF_FMRI_SERVICE_PREFIX) - 1;

		/* If the scope ends with the suffix, remove it. */
		te = strstr(my_scope, SCF_FMRI_SCOPE_SUFFIX);
		if (te != NULL && te[sizeof (SCF_FMRI_SCOPE_SUFFIX) - 1] == 0)
			*te = 0;

		/* Validate the scope. */
		if (my_scope[0] == '\0')
			my_scope = SCF_FMRI_LOCAL_SCOPE;
		else if (uu_check_name(my_scope, 0) == -1) {
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
		}

		if (scope != NULL)
			*scope = my_scope;
	} else {
		if (scope != NULL)
			*scope = SCF_FMRI_LOCAL_SCOPE;
	}

	if (s[0] != 0) {
		if (strncmp(s, SCF_FMRI_SERVICE_PREFIX,
		    sizeof (SCF_FMRI_SERVICE_PREFIX) - 1) == 0)
			s += sizeof (SCF_FMRI_SERVICE_PREFIX) - 1;

		/*
		 * Can't validate service here because it might not be null
		 * terminated.
		 */
		my_s = s;
	}

	tpg = strstr(s, SCF_FMRI_PROPERTYGRP_PREFIX);
	te = strstr(s, SCF_FMRI_INSTANCE_PREFIX);
	if (te != NULL && (tpg == NULL || te < tpg)) {
		*te = 0;
		te += sizeof (SCF_FMRI_INSTANCE_PREFIX) - 1;

		/* Can't validate instance here either. */
		my_i = s = te;

		te = strstr(s, SCF_FMRI_PROPERTYGRP_PREFIX);
	} else {
		te = tpg;
	}

	if (te != NULL) {
		*te = 0;
		te += sizeof (SCF_FMRI_PROPERTYGRP_PREFIX) - 1;

		my_pg = s = te;
		te = strstr(s, SCF_FMRI_PROPERTY_PREFIX);
		if (te != NULL) {
			*te = 0;
			te += sizeof (SCF_FMRI_PROPERTY_PREFIX) - 1;

			my_p = te;
			s = te;
		}
	}

	if (my_s != NULL) {
		if (uu_check_name(my_s, UU_NAME_DOMAIN | UU_NAME_PATH) == -1)
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

		if (service != NULL)
			*service = my_s;
	}

	if (my_i != NULL) {
		if (uu_check_name(my_i, UU_NAME_DOMAIN) == -1)
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

		if (instance != NULL)
			*instance = my_i;
	}

	if (my_pg != NULL) {
		if (uu_check_name(my_pg, UU_NAME_DOMAIN) == -1)
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

		if (propertygroup != NULL)
			*propertygroup = my_pg;
	}

	if (my_p != NULL) {
		if (uu_check_name(my_p, UU_NAME_DOMAIN) == -1)
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

		if (property != NULL)
			*property = my_p;
	}

	return (0);
}

int
scf_parse_file_fmri(char *fmri, const char **scope, const char **path)
{
	char *s, *e, *te;

	if (scope != NULL)
		*scope = NULL;

	s = fmri;
	e = strchr(s, '\0');

	if (strncmp(s, SCF_FMRI_FILE_PREFIX,
	    sizeof (SCF_FMRI_FILE_PREFIX) - 1) == 0)
		s += sizeof (SCF_FMRI_FILE_PREFIX) - 1;

	if (strncmp(s, SCF_FMRI_SCOPE_PREFIX,
	    sizeof (SCF_FMRI_SCOPE_PREFIX) - 1) == 0) {
		char *my_scope;

		s += sizeof (SCF_FMRI_SCOPE_PREFIX) - 1;
		te = strstr(s, SCF_FMRI_SERVICE_PREFIX);
		if (te == NULL)
			te = e;

		*te = 0;
		my_scope = s;

		s = te;

		/* Validate the scope. */
		if (my_scope[0] != '\0' &&
		    strcmp(my_scope, SCF_FMRI_LOCAL_SCOPE) != 0) {
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
		}

		if (scope != NULL)
			*scope = my_scope;
	} else {
		/*
		 * FMRI paths must be absolute
		 */
		if (s[0] != '/')
			return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));
	}

	s += sizeof (SCF_FMRI_SERVICE_PREFIX) - 1;

	if (s >= e)
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	/*
	 * If the user requests it, return the full path of the file.
	 */
	if (path != NULL) {
		assert(s > fmri);
		s[-1] = '/';
		*path = s - 1;
	}

	return (0);
}

int
scf_parse_fmri(char *fmri, int *type, const char **scope, const char **service,
    const char **instance, const char **propertygroup, const char **property)
{
	if (strncmp(fmri, SCF_FMRI_SVC_PREFIX,
	    sizeof (SCF_FMRI_SVC_PREFIX) - 1) == 0) {
		if (type)
			*type = SCF_FMRI_TYPE_SVC;
		return (scf_parse_svc_fmri(fmri, scope, service, instance,
		    propertygroup, property));
	} else if (strncmp(fmri, SCF_FMRI_FILE_PREFIX,
	    sizeof (SCF_FMRI_FILE_PREFIX) - 1) == 0) {
		if (type)
			*type = SCF_FMRI_TYPE_FILE;
		return (scf_parse_file_fmri(fmri, scope, NULL));
	} else {
		/*
		 * Parse as a svc if the fmri type is not explicitly
		 * specified.
		 */
		if (type)
			*type = SCF_FMRI_TYPE_SVC;
		return (scf_parse_svc_fmri(fmri, scope, service, instance,
		    propertygroup, property));
	}
}

/*
 * Fails with _INVALID_ARGUMENT.  fmri and buf may be equal.
 */
ssize_t
scf_canonify_fmri(const char *fmri, char *buf, size_t bufsz)
{
	const char *scope, *service, *instance, *pg, *property;
	char local[6 * REP_PROTOCOL_NAME_LEN];
	int r;
	size_t len;

	if (strlcpy(local, fmri, sizeof (local)) >= sizeof (local)) {
		/* Should this be CONSTRAINT_VIOLATED? */
		(void) scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		return (-1);
	}


	r = scf_parse_svc_fmri(local, &scope, &service, &instance, &pg,
	    &property);
	if (r != 0)
		return (-1);

	len = strlcpy(buf, "svc:/", bufsz);

	if (scope != NULL && strcmp(scope, SCF_SCOPE_LOCAL) != 0) {
		len += strlcat(buf, "/", bufsz);
		len += strlcat(buf, scope, bufsz);
	}

	if (service)
		len += strlcat(buf, service, bufsz);

	if (instance) {
		len += strlcat(buf, ":", bufsz);
		len += strlcat(buf, instance, bufsz);
	}

	if (pg) {
		len += strlcat(buf, "/:properties/", bufsz);
		len += strlcat(buf, pg, bufsz);
	}

	if (property) {
		len += strlcat(buf, "/", bufsz);
		len += strlcat(buf, property, bufsz);
	}

	return (len);
}

/*
 * Fails with _HANDLE_MISMATCH, _INVALID_ARGUMENT, _CONSTRAINT_VIOLATED,
 * _NOT_FOUND, _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL, _NOT_SET, _DELETED,
 * _NO_RESOURCES, _BACKEND_ACCESS.
 */
int
scf_handle_decode_fmri(scf_handle_t *h, const char *fmri, scf_scope_t *sc,
    scf_service_t *svc, scf_instance_t *inst, scf_propertygroup_t *pg,
    scf_property_t *prop, int flags)
{
	const char *scope, *service, *instance, *propertygroup, *property;
	int last;
	char local[6 * REP_PROTOCOL_NAME_LEN];
	int ret;
	const uint32_t holds = RH_HOLD_SCOPE | RH_HOLD_SERVICE |
	    RH_HOLD_INSTANCE | RH_HOLD_PG | RH_HOLD_PROPERTY;

	/*
	 * verify that all handles match
	 */
	if ((sc != NULL && h != sc->rd_d.rd_handle) ||
	    (svc != NULL && h != svc->rd_d.rd_handle) ||
	    (inst != NULL && h != inst->rd_d.rd_handle) ||
	    (pg != NULL && h != pg->rd_d.rd_handle) ||
	    (prop != NULL && h != prop->rd_d.rd_handle))
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	if (strlcpy(local, fmri, sizeof (local)) >= sizeof (local)) {
		ret = scf_set_error(SCF_ERROR_INVALID_ARGUMENT);
		goto reset_args;
	}

	/*
	 * We can simply return from an error in parsing, because
	 * scf_parse_fmri sets the error code correctly.
	 */
	if (scf_parse_svc_fmri(local, &scope, &service, &instance,
	    &propertygroup, &property) == -1) {
		ret = -1;
		goto reset_args;
	}

	/*
	 * the FMRI looks valid at this point -- do constraint checks.
	 */

	if (instance != NULL && (flags & SCF_DECODE_FMRI_REQUIRE_NO_INSTANCE)) {
		ret = scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
		goto reset_args;
	}
	if (instance == NULL && (flags & SCF_DECODE_FMRI_REQUIRE_INSTANCE)) {
		ret = scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
		goto reset_args;
	}

	if (prop != NULL)
		last = REP_PROTOCOL_ENTITY_PROPERTY;
	else if (pg != NULL)
		last = REP_PROTOCOL_ENTITY_PROPERTYGRP;
	else if (inst != NULL)
		last = REP_PROTOCOL_ENTITY_INSTANCE;
	else if (svc != NULL)
		last = REP_PROTOCOL_ENTITY_SERVICE;
	else if (sc != NULL)
		last = REP_PROTOCOL_ENTITY_SCOPE;
	else
		last = REP_PROTOCOL_ENTITY_NONE;

	if (flags & SCF_DECODE_FMRI_EXACT) {
		int last_fmri;

		if (property != NULL)
			last_fmri = REP_PROTOCOL_ENTITY_PROPERTY;
		else if (propertygroup != NULL)
			last_fmri = REP_PROTOCOL_ENTITY_PROPERTYGRP;
		else if (instance != NULL)
			last_fmri = REP_PROTOCOL_ENTITY_INSTANCE;
		else if (service != NULL)
			last_fmri = REP_PROTOCOL_ENTITY_SERVICE;
		else if (scope != NULL)
			last_fmri = REP_PROTOCOL_ENTITY_SCOPE;
		else
			last_fmri = REP_PROTOCOL_ENTITY_NONE;

		if (last != last_fmri) {
			ret = scf_set_error(SCF_ERROR_CONSTRAINT_VIOLATED);
			goto reset_args;
		}
	}

	if ((flags & SCF_DECODE_FMRI_TRUNCATE) &&
	    last == REP_PROTOCOL_ENTITY_NONE) {
		ret = 0;				/* nothing to do */
		goto reset_args;
	}

	if (!(flags & SCF_DECODE_FMRI_TRUNCATE))
		last = REP_PROTOCOL_ENTITY_NONE;	/* never stop */

	/*
	 * passed the constraint checks -- try to grab the thing itself.
	 */

	handle_hold_subhandles(h, holds);
	if (sc == NULL)
		sc = h->rh_scope;
	else
		datael_reset(&sc->rd_d);

	if (svc == NULL)
		svc = h->rh_service;
	else
		datael_reset(&svc->rd_d);

	if (inst == NULL)
		inst = h->rh_instance;
	else
		datael_reset(&inst->rd_d);

	if (pg == NULL)
		pg = h->rh_pg;
	else
		datael_reset(&pg->rd_d);

	if (prop == NULL)
		prop = h->rh_property;
	else
		datael_reset(&prop->rd_d);

	/*
	 * We only support local scopes, but we check *after* getting
	 * the local scope, so that any repository-related errors take
	 * precedence.
	 */
	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, sc) == -1) {
		handle_rele_subhandles(h, holds);
		ret = -1;
		goto reset_args;
	}

	if (scope != NULL && strcmp(scope, SCF_FMRI_LOCAL_SCOPE) != 0) {
		handle_rele_subhandles(h, holds);
		ret = scf_set_error(SCF_ERROR_NOT_FOUND);
		goto reset_args;
	}


	if (service == NULL || last == REP_PROTOCOL_ENTITY_SCOPE) {
		handle_rele_subhandles(h, holds);
		return (0);
	}

	if (scf_scope_get_service(sc, service, svc) == -1) {
		handle_rele_subhandles(h, holds);
		ret = -1;
		assert(scf_error() != SCF_ERROR_NOT_SET);
		if (scf_error() == SCF_ERROR_DELETED)
			(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		goto reset_args;
	}

	if (last == REP_PROTOCOL_ENTITY_SERVICE) {
		handle_rele_subhandles(h, holds);
		return (0);
	}

	if (instance == NULL) {
		if (propertygroup == NULL ||
		    last == REP_PROTOCOL_ENTITY_INSTANCE) {
			handle_rele_subhandles(h, holds);
			return (0);
		}

		if (scf_service_get_pg(svc, propertygroup, pg) == -1) {
			handle_rele_subhandles(h, holds);
			ret = -1;
			assert(scf_error() != SCF_ERROR_NOT_SET);
			if (scf_error() == SCF_ERROR_DELETED)
				(void) scf_set_error(SCF_ERROR_NOT_FOUND);
			goto reset_args;
		}
	} else {
		if (scf_service_get_instance(svc, instance, inst) == -1) {
			handle_rele_subhandles(h, holds);
			ret = -1;
			assert(scf_error() != SCF_ERROR_NOT_SET);
			if (scf_error() == SCF_ERROR_DELETED)
				(void) scf_set_error(SCF_ERROR_NOT_FOUND);
			goto reset_args;
		}

		if (propertygroup == NULL ||
		    last == REP_PROTOCOL_ENTITY_INSTANCE) {
			handle_rele_subhandles(h, holds);
			return (0);
		}

		if (scf_instance_get_pg(inst, propertygroup, pg) == -1) {
			handle_rele_subhandles(h, holds);
			ret = -1;
			assert(scf_error() != SCF_ERROR_NOT_SET);
			if (scf_error() == SCF_ERROR_DELETED)
				(void) scf_set_error(SCF_ERROR_NOT_FOUND);
			goto reset_args;
		}
	}

	if (property == NULL || last == REP_PROTOCOL_ENTITY_PROPERTYGRP) {
		handle_rele_subhandles(h, holds);
		return (0);
	}

	if (scf_pg_get_property(pg, property, prop) == -1) {
		handle_rele_subhandles(h, holds);
		ret = -1;
		assert(scf_error() != SCF_ERROR_NOT_SET);
		if (scf_error() == SCF_ERROR_DELETED)
			(void) scf_set_error(SCF_ERROR_NOT_FOUND);
		goto reset_args;
	}

	handle_rele_subhandles(h, holds);
	return (0);

reset_args:
	if (sc != NULL)
		datael_reset(&sc->rd_d);
	if (svc != NULL)
		datael_reset(&svc->rd_d);
	if (inst != NULL)
		datael_reset(&inst->rd_d);
	if (pg != NULL)
		datael_reset(&pg->rd_d);
	if (prop != NULL)
		datael_reset(&prop->rd_d);

	return (ret);
}

/*
 * Fails with _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL (server response too
 * big, bad entity id, request not applicable to entity, name too long for
 * buffer), _NOT_SET, or _DELETED.
 */
ssize_t
scf_scope_to_fmri(const scf_scope_t *scope, char *out, size_t sz)
{
	ssize_t r, len;

	char tmp[REP_PROTOCOL_NAME_LEN];

	r = scf_scope_get_name(scope, tmp, sizeof (tmp));

	if (r <= 0)
		return (r);

	len = strlcpy(out, SCF_FMRI_SVC_PREFIX, sz);
	if (strcmp(tmp, SCF_FMRI_LOCAL_SCOPE) != 0) {
		if (len >= sz)
			return (len + r + sizeof (SCF_FMRI_SCOPE_SUFFIX) - 1);

		len = strlcat(out, tmp, sz);
		if (len >= sz)
			return (len + sizeof (SCF_FMRI_SCOPE_SUFFIX) - 1);
		len = strlcat(out,
		    SCF_FMRI_SCOPE_SUFFIX SCF_FMRI_SERVICE_PREFIX, sz);
	}

	return (len);
}

/*
 * Fails with _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL (server response too
 * big, bad element id, bad ids, bad types, scope has no parent, request not
 * applicable to entity, name too long), _NOT_SET, _DELETED,
 */
ssize_t
scf_service_to_fmri(const scf_service_t *svc, char *out, size_t sz)
{
	scf_handle_t *h = svc->rd_d.rd_handle;
	scf_scope_t *scope = HANDLE_HOLD_SCOPE(h);
	ssize_t r, len;

	char tmp[REP_PROTOCOL_NAME_LEN];

	r = datael_get_parent(&svc->rd_d, &scope->rd_d);
	if (r != SCF_SUCCESS) {
		HANDLE_RELE_SCOPE(h);

		assert(scf_error() != SCF_ERROR_HANDLE_MISMATCH);
		return (-1);
	}
	if (out != NULL && sz > 0)
		len = scf_scope_to_fmri(scope, out, sz);
	else
		len = scf_scope_to_fmri(scope, tmp, 2);

	HANDLE_RELE_SCOPE(h);

	if (len < 0)
		return (-1);

	if (out == NULL || len >= sz)
		len += sizeof (SCF_FMRI_SERVICE_PREFIX) - 1;
	else
		len = strlcat(out, SCF_FMRI_SERVICE_PREFIX, sz);

	r = scf_service_get_name(svc, tmp, sizeof (tmp));
	if (r < 0)
		return (r);

	if (out == NULL || len >= sz)
		len += r;
	else
		len = strlcat(out, tmp, sz);

	return (len);
}

ssize_t
scf_instance_to_fmri(const scf_instance_t *inst, char *out, size_t sz)
{
	scf_handle_t *h = inst->rd_d.rd_handle;
	scf_service_t *svc = HANDLE_HOLD_SERVICE(h);
	ssize_t r, len;

	char tmp[REP_PROTOCOL_NAME_LEN];

	r = datael_get_parent(&inst->rd_d, &svc->rd_d);
	if (r != SCF_SUCCESS) {
		HANDLE_RELE_SERVICE(h);
		return (-1);
	}

	len = scf_service_to_fmri(svc, out, sz);

	HANDLE_RELE_SERVICE(h);

	if (len < 0)
		return (len);

	if (len >= sz)
		len += sizeof (SCF_FMRI_INSTANCE_PREFIX) - 1;
	else
		len = strlcat(out, SCF_FMRI_INSTANCE_PREFIX, sz);

	r = scf_instance_get_name(inst, tmp, sizeof (tmp));
	if (r < 0)
		return (r);

	if (len >= sz)
		len += r;
	else
		len = strlcat(out, tmp, sz);

	return (len);
}

ssize_t
scf_pg_to_fmri(const scf_propertygroup_t *pg, char *out, size_t sz)
{
	scf_handle_t *h = pg->rd_d.rd_handle;

	struct rep_protocol_entity_parent_type request;
	struct rep_protocol_integer_response response;

	char tmp[REP_PROTOCOL_NAME_LEN];
	ssize_t len, r;

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_ENTITY_PARENT_TYPE;
	request.rpr_entityid = pg->rd_d.rd_entity;

	datael_finish_reset(&pg->rd_d);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0)
		DOOR_ERRORS_BLOCK(r);

	if (response.rpr_response != REP_PROTOCOL_SUCCESS ||
	    r < sizeof (response)) {
		return (scf_set_error(proto_error(response.rpr_response)));
	}

	switch (response.rpr_value) {
	case REP_PROTOCOL_ENTITY_SERVICE: {
		scf_service_t *svc;

		svc = HANDLE_HOLD_SERVICE(h);

		r = datael_get_parent(&pg->rd_d, &svc->rd_d);

		if (r == SCF_SUCCESS)
			len = scf_service_to_fmri(svc, out, sz);

		HANDLE_RELE_SERVICE(h);
		break;
	}

	case REP_PROTOCOL_ENTITY_INSTANCE: {
		scf_instance_t *inst;

		inst = HANDLE_HOLD_INSTANCE(h);

		r = datael_get_parent(&pg->rd_d, &inst->rd_d);

		if (r == SCF_SUCCESS)
			len = scf_instance_to_fmri(inst, out, sz);

		HANDLE_RELE_INSTANCE(h);
		break;
	}

	case REP_PROTOCOL_ENTITY_SNAPLEVEL: {
		scf_instance_t *inst = HANDLE_HOLD_INSTANCE(h);
		scf_snapshot_t *snap = HANDLE_HOLD_SNAPSHOT(h);
		scf_snaplevel_t *level = HANDLE_HOLD_SNAPLVL(h);

		r = datael_get_parent(&pg->rd_d, &level->rd_d);

		if (r == SCF_SUCCESS)
			r = datael_get_parent(&level->rd_d, &snap->rd_d);

		if (r == SCF_SUCCESS)
			r = datael_get_parent(&snap->rd_d, &inst->rd_d);

		if (r == SCF_SUCCESS)
			len = scf_instance_to_fmri(inst, out, sz);

		HANDLE_RELE_INSTANCE(h);
		HANDLE_RELE_SNAPSHOT(h);
		HANDLE_RELE_SNAPLVL(h);
		break;
	}

	default:
		return (scf_set_error(SCF_ERROR_INTERNAL));
	}

	if (r != SCF_SUCCESS)
		return (r);

	if (len >= sz)
		len += sizeof (SCF_FMRI_PROPERTYGRP_PREFIX) - 1;
	else
		len = strlcat(out, SCF_FMRI_PROPERTYGRP_PREFIX, sz);

	r = scf_pg_get_name(pg, tmp, sizeof (tmp));

	if (r < 0)
		return (r);

	if (len >= sz)
		len += r;
	else
		len = strlcat(out, tmp, sz);

	return (len);
}

ssize_t
scf_property_to_fmri(const scf_property_t *prop, char *out, size_t sz)
{
	scf_handle_t *h = prop->rd_d.rd_handle;
	scf_propertygroup_t *pg = HANDLE_HOLD_PG(h);

	char tmp[REP_PROTOCOL_NAME_LEN];
	ssize_t len;
	int r;

	r = datael_get_parent(&prop->rd_d, &pg->rd_d);
	if (r != SCF_SUCCESS) {
		HANDLE_RELE_PG(h);
		return (-1);
	}

	len = scf_pg_to_fmri(pg, out, sz);

	HANDLE_RELE_PG(h);

	if (len >= sz)
		len += sizeof (SCF_FMRI_PROPERTY_PREFIX) - 1;
	else
		len = strlcat(out, SCF_FMRI_PROPERTY_PREFIX, sz);

	r = scf_property_get_name(prop, tmp, sizeof (tmp));

	if (r < 0)
		return (r);

	if (len >= sz)
		len += r;
	else
		len = strlcat(out, tmp, sz);

	return (len);
}

/*
 * Fails with _HANDLE_MISMATCH, _NOT_BOUND, _CONNECTION_BROKEN, _INTERNAL
 * (server response too big, bad entity id, request not applicable to entity,
 * name too long for buffer, bad element id, iter already exists, element
 * cannot have children of type, type is invalid, iter was reset, sequence
 * was bad, iter walks values, iter does not walk type entities),
 * _NOT_SET, _DELETED, or _CONSTRAINT_VIOLATED,
 * _NOT_FOUND (scope has no parent),  _INVALID_ARGUMENT, _NO_RESOURCES,
 * _BACKEND_ACCESS.
 */
int
scf_pg_get_underlying_pg(const scf_propertygroup_t *pg,
    scf_propertygroup_t *out)
{
	scf_handle_t *h = pg->rd_d.rd_handle;
	scf_service_t *svc;
	scf_instance_t *inst;

	char me[REP_PROTOCOL_NAME_LEN];
	int r;

	if (h != out->rd_d.rd_handle)
		return (scf_set_error(SCF_ERROR_HANDLE_MISMATCH));

	r = scf_pg_get_name(pg, me, sizeof (me));

	if (r < 0)
		return (r);

	svc = HANDLE_HOLD_SERVICE(h);
	inst = HANDLE_HOLD_INSTANCE(h);

	r = datael_get_parent(&pg->rd_d, &inst->rd_d);

	if (r == SCF_SUCCESS) {
		r = datael_get_parent(&inst->rd_d, &svc->rd_d);
		if (r != SCF_SUCCESS) {
			goto out;
		}
		r = scf_service_get_pg(svc, me, out);
	} else {
		r = scf_set_error(SCF_ERROR_NOT_FOUND);
	}

out:
	HANDLE_RELE_SERVICE(h);
	HANDLE_RELE_INSTANCE(h);
	return (r);
}

#define	LEGACY_SCHEME	"lrc:"
#define	LEGACY_UNKNOWN	"unknown"

/*
 * Implementation of scf_walk_fmri()
 *
 * This is a little tricky due to the many-to-many relationship between patterns
 * and matches.  We need to be able to satisfy the following requirements:
 *
 * 	1) Detect patterns which match more than one FMRI, and be able to
 *         report which FMRIs have been matched.
 * 	2) Detect patterns which have not matched any FMRIs
 * 	3) Visit each matching FMRI exactly once across all patterns
 * 	4) Ignore FMRIs which have only been matched due to multiply-matching
 *         patterns.
 *
 * We maintain an array of scf_pattern_t structures, one for each argument, and
 * maintain a linked list of scf_match_t structures for each one.  We first
 * qualify each pattern's type:
 *
 *	PATTERN_INVALID		The argument is invalid (too long).
 *
 *	PATTERN_EXACT		The pattern is a complete FMRI.  The list of
 *				matches contains only a single entry.
 *
 * 	PATTERN_GLOB		The pattern will be matched against all
 * 				FMRIs via fnmatch() in the second phase.
 * 				Matches will be added to the pattern's list
 * 				as they are found.
 *
 * 	PATTERN_PARTIAL		Everything else.  We will assume that this is
 * 				an abbreviated FMRI, and match according to
 * 				our abbreviated FMRI rules.  Matches will be
 * 				added to the pattern's list as they are found.
 *
 * The first pass searches for arguments that are complete FMRIs.  These are
 * classified as EXACT patterns and do not necessitate searching the entire
 * tree.
 *
 * Once this is done, if we have any GLOB or PARTIAL patterns (or if no
 * arguments were given), we iterate over all services and instances in the
 * repository, looking for matches.
 *
 * When a match is found, we add the match to the pattern's list.  We also enter
 * the match into a hash table, resulting in something like this:
 *
 *       scf_pattern_t       scf_match_t
 *     +---------------+      +-------+     +-------+
 *     | pattern 'foo' |----->| match |---->| match |
 *     +---------------+      +-------+     +-------+
 *                                |             |
 *           scf_match_key_t      |             |
 *           +--------------+     |             |
 *           | FMRI bar/foo |<----+             |
 *           +--------------+                   |
 *           | FMRI baz/foo |<------------------+
 *           +--------------+
 *
 * Once we have all of this set up, we do one pass to report patterns matching
 * multiple FMRIs (if SCF_WALK_MULTIPLE is not set) and patterns for which no
 * match was found.
 *
 * Finally, we walk through all valid patterns, and for each match, if we
 * haven't already seen the match (as recorded in the hash table), then we
 * execute the callback.
 */

struct scf_matchkey;
struct scf_match;

/*
 * scf_matchkey_t
 */
typedef struct scf_matchkey {
	char			*sk_fmri;	/* Matching FMRI */
	char			*sk_legacy;	/* Legacy name */
	int			sk_seen;	/* If we've been seen */
	struct scf_matchkey	*sk_next;	/* Next in hash chain */
} scf_matchkey_t;

/*
 * scf_match_t
 */
typedef struct scf_match {
	scf_matchkey_t		*sm_key;
	struct scf_match	*sm_next;
} scf_match_t;

#define	WALK_HTABLE_SIZE	123

/*
 * scf_get_key()
 *
 * Given an FMRI and a hash table, returns the scf_matchkey_t corresponding to
 * this FMRI.  If the FMRI does not exist, it is added to the hash table.  If a
 * new entry cannot be allocated due to lack of memory, NULL is returned.
 */
static scf_matchkey_t *
scf_get_key(scf_matchkey_t **htable, const char *fmri, const char *legacy)
{
	uint_t h = 0, g;
	const char *p, *k;
	scf_matchkey_t *key;

	k = strstr(fmri, ":/");
	assert(k != NULL);
	k += 2;

	/*
	 * Generic hash function from uts/common/os/modhash.c.
	 */
	for (p = k; *p != '\0'; ++p) {
		h = (h << 4) + *p;
		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	h %= WALK_HTABLE_SIZE;

	/*
	 * Search for an existing key
	 */
	for (key = htable[h]; key != NULL; key = key->sk_next) {
		if (strcmp(key->sk_fmri, fmri) == 0)
			return (key);
	}

	if ((key = calloc(sizeof (scf_matchkey_t), 1)) == NULL)
		return (NULL);

	/*
	 * Add new key to hash table.
	 */
	if ((key->sk_fmri = strdup(fmri)) == NULL) {
		free(key);
		return (NULL);
	}

	if (legacy == NULL) {
		key->sk_legacy = NULL;
	} else if ((key->sk_legacy = strdup(legacy)) == NULL) {
		free(key->sk_fmri);
		free(key);
		return (NULL);
	}

	key->sk_next = htable[h];
	htable[h] = key;

	return (key);
}

/*
 * Given an FMRI, insert it into the pattern's list appropriately.
 * svc_explicit indicates whether matching services should take
 * precedence over matching instances.
 */
static scf_error_t
scf_add_match(scf_matchkey_t **htable, const char *fmri, const char *legacy,
    scf_pattern_t *pattern, int svc_explicit)
{
	scf_match_t *match;

	/*
	 * If svc_explicit is set, enforce the constaint that matching
	 * instances take precedence over matching services. Otherwise,
	 * matching services take precedence over matching instances.
	 */
	if (svc_explicit) {
		scf_match_t *next, *prev;
		/*
		 * If we match an instance, check to see if we must remove
		 * any matching services (for SCF_WALK_EXPLICIT).
		 */
		for (prev = match = pattern->sp_matches; match != NULL;
		    match = next) {
			size_t len = strlen(match->sm_key->sk_fmri);
			next = match->sm_next;
			if (strncmp(match->sm_key->sk_fmri, fmri, len) == 0 &&
			    fmri[len] == ':') {
				if (prev == match)
					pattern->sp_matches = match->sm_next;
				else
					prev->sm_next = match->sm_next;
				pattern->sp_matchcount--;
				free(match);
			} else
				prev = match;
		}
	} else {
		/*
		 * If we've matched a service don't add any instances (for
		 * SCF_WALK_SERVICE).
		 */
		for (match = pattern->sp_matches; match != NULL;
		    match = match->sm_next) {
			size_t len = strlen(match->sm_key->sk_fmri);
			if (strncmp(match->sm_key->sk_fmri, fmri, len) == 0 &&
			    fmri[len] == ':')
				return (0);
		}
	}

	if ((match = malloc(sizeof (scf_match_t))) == NULL)
		return (SCF_ERROR_NO_MEMORY);

	if ((match->sm_key = scf_get_key(htable, fmri, legacy)) == NULL) {
		free(match);
		return (SCF_ERROR_NO_MEMORY);
	}

	match->sm_next = pattern->sp_matches;
	pattern->sp_matches = match;
	pattern->sp_matchcount++;

	return (0);
}

/*
 * Returns 1 if the fmri matches the given pattern, 0 otherwise.
 */
int
scf_cmp_pattern(char *fmri, scf_pattern_t *pattern)
{
	char *tmp;

	if (pattern->sp_type == PATTERN_GLOB) {
		if (fnmatch(pattern->sp_arg, fmri, 0) == 0)
			return (1);
	} else if (pattern->sp_type == PATTERN_PARTIAL &&
	    (tmp = strstr(fmri, pattern->sp_arg)) != NULL) {
		/*
		 * We only allow partial matches anchored on the end of
		 * a service or instance, and beginning on an element
		 * boundary.
		 */
		if (tmp != fmri && tmp[-1] != '/' && tmp[-1] != ':' &&
		    tmp[0] != ':')
			return (0);
		tmp += strlen(pattern->sp_arg);
		if (tmp != fmri + strlen(fmri) && tmp[0] != ':' &&
		    tmp[-1] != ':')
			return (0);

		/*
		 * If the user has supplied a short pattern that matches
		 * 'svc:/' or 'lrc:/', ignore it.
		 */
		if (tmp <= fmri + 4)
			return (0);

		return (1);
	}

	return (0);
}

/*
 * Attempts to match the given FMRI against a set of patterns, keeping track of
 * the results.
 */
static scf_error_t
scf_pattern_match(scf_matchkey_t **htable, char *fmri, const char *legacy,
    int npattern, scf_pattern_t *pattern, int svc_explicit)
{
	int i;
	int ret = 0;

	for (i = 0; i < npattern; i++) {
		if (scf_cmp_pattern(fmri, &pattern[i]) &&
		    (ret = scf_add_match(htable, fmri,
		    legacy, &pattern[i], svc_explicit)) != 0)
			return (ret);
	}

	return (0);
}

/*
 * Fails with _INVALID_ARGUMENT, _HANDLE_DESTROYED, _INTERNAL (bad server
 * response or id in use), _NO_MEMORY, _HANDLE_MISMATCH, _CONSTRAINT_VIOLATED,
 * _NOT_FOUND, _NOT_BOUND, _CONNECTION_BROKEN, _NOT_SET, _DELETED,
 * _NO_RESOURCES, _BACKEND_ACCESS, _TYPE_MISMATCH.
 */
scf_error_t
scf_walk_fmri(scf_handle_t *h, int argc, char **argv, int flags,
    scf_walk_callback callback, void *data, int *err,
    void (*errfunc)(const char *, ...))
{
	scf_pattern_t *pattern = NULL;
	int i;
	char *fmri = NULL;
	ssize_t max_fmri_length;
	scf_service_t *svc = NULL;
	scf_instance_t *inst = NULL;
	scf_iter_t *iter = NULL, *sciter = NULL, *siter = NULL;
	scf_scope_t *scope = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	int ret = 0;
	scf_matchkey_t **htable = NULL;
	int pattern_search = 0;
	ssize_t max_name_length;
	char *pgname = NULL;
	scf_walkinfo_t info;
	boolean_t partial_fmri = B_FALSE;
	boolean_t wildcard_fmri = B_FALSE;

#ifndef NDEBUG
	if (flags & SCF_WALK_EXPLICIT)
		assert(flags & SCF_WALK_SERVICE);
	if (flags & SCF_WALK_NOINSTANCE)
		assert(flags & SCF_WALK_SERVICE);
	if (flags & SCF_WALK_PROPERTY)
		assert(!(flags & SCF_WALK_LEGACY));
#endif

	/*
	 * Setup initial variables
	 */
	max_fmri_length = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	assert(max_fmri_length != -1);
	max_name_length = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	assert(max_name_length != -1);

	if ((fmri = malloc(max_fmri_length + 1)) == NULL ||
	    (pgname = malloc(max_name_length + 1)) == NULL) {
		ret = SCF_ERROR_NO_MEMORY;
		goto error;
	}

	if (argc == 0) {
		pattern = NULL;
	} else if ((pattern = calloc(argc, sizeof (scf_pattern_t)))
	    == NULL) {
		ret = SCF_ERROR_NO_MEMORY;
		goto error;
	}

	if ((htable = calloc(WALK_HTABLE_SIZE, sizeof (void *))) == NULL) {
		ret = SCF_ERROR_NO_MEMORY;
		goto error;
	}

	if ((inst = scf_instance_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL ||
	    (sciter = scf_iter_create(h)) == NULL ||
	    (siter = scf_iter_create(h)) == NULL ||
	    (scope = scf_scope_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (value = scf_value_create(h)) == NULL) {
		ret = scf_error();
		goto error;
	}

	/*
	 * For each fmri given, we first check to see if it's a full service,
	 * instance, property group, or property FMRI.  This avoids having to do
	 * the (rather expensive) walk of all instances.  Any element which does
	 * not match a full fmri is identified as a globbed pattern or a partial
	 * fmri and stored in a private array when walking instances.
	 */
	for (i = 0; i < argc; i++) {
		const char *scope_name, *svc_name, *inst_name, *pg_name;
		const char *prop_name;

		if (strlen(argv[i]) > max_fmri_length) {
			errfunc(scf_get_msg(SCF_MSG_ARGTOOLONG), argv[i]);
			if (err != NULL)
				*err = UU_EXIT_FATAL;
			continue;
		}

		(void) strcpy(fmri, argv[i]);
		if (scf_parse_svc_fmri(fmri, &scope_name, &svc_name, &inst_name,
		    &pg_name, &prop_name) != SCF_SUCCESS)
			goto badfmri;

		/*
		 * If the user has specified SCF_WALK_PROPERTY, allow property
		 * groups and properties.
		 */
		if (pg_name != NULL || prop_name != NULL) {
			if (!(flags & SCF_WALK_PROPERTY))
				goto badfmri;

			if (scf_handle_decode_fmri(h, argv[i], NULL, NULL,
			    NULL, pg, prop, 0) != 0)
				goto badfmri;

			if (scf_pg_get_name(pg, NULL, 0) < 0 &&
			    scf_property_get_name(prop, NULL, 0) < 0)
				goto badfmri;

			if (scf_canonify_fmri(argv[i], fmri, max_fmri_length)
			    <= 0) {
				/*
				 * scf_parse_fmri() should have caught this.
				 */
				abort();
			}

			if ((ret = scf_add_match(htable, fmri, NULL,
			    &pattern[i], flags & SCF_WALK_EXPLICIT)) != 0)
				goto error;

			if ((pattern[i].sp_arg = strdup(argv[i])) == NULL) {
				ret = SCF_ERROR_NO_MEMORY;
				goto error;
			}
			pattern[i].sp_type = PATTERN_EXACT;
		}

		/*
		 * We need at least a service name
		 */
		if (scope_name == NULL || svc_name == NULL)
			goto badfmri;

		/*
		 * If we have a fully qualified instance, add it to our list of
		 * fmris to watch.
		 */
		if (inst_name != NULL) {
			if (flags & SCF_WALK_NOINSTANCE)
				goto badfmri;

			if (scf_handle_decode_fmri(h, argv[i], NULL, NULL,
			    inst, NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0)
				goto badfmri;

			if (scf_canonify_fmri(argv[i], fmri, max_fmri_length)
			    <= 0)
				goto badfmri;

			if ((ret = scf_add_match(htable, fmri, NULL,
			    &pattern[i], flags & SCF_WALK_EXPLICIT)) != 0)
				goto error;

			if ((pattern[i].sp_arg = strdup(argv[i])) == NULL) {
				ret = SCF_ERROR_NO_MEMORY;
				goto error;
			}
			pattern[i].sp_type = PATTERN_EXACT;

			continue;
		}

		if (scf_handle_decode_fmri(h, argv[i], NULL, svc,
		    NULL, NULL, NULL, SCF_DECODE_FMRI_EXACT) !=
		    SCF_SUCCESS)
			goto badfmri;

		/*
		 * If the user allows for bare services, then simply
		 * pass this service on.
		 */
		if (flags & SCF_WALK_SERVICE) {
			if (scf_service_to_fmri(svc, fmri,
			    max_fmri_length + 1) <= 0) {
				ret = scf_error();
				goto error;
			}

			if ((ret = scf_add_match(htable, fmri, NULL,
			    &pattern[i], flags & SCF_WALK_EXPLICIT)) != 0)
				goto error;

			if ((pattern[i].sp_arg = strdup(argv[i]))
			    == NULL) {
				ret = SCF_ERROR_NO_MEMORY;
				goto error;
			}
			pattern[i].sp_type = PATTERN_EXACT;
			continue;
		}

		if (flags & SCF_WALK_NOINSTANCE)
			goto badfmri;

		/*
		 * Otherwise, iterate over all instances in the service.
		 */
		if (scf_iter_service_instances(iter, svc) !=
		    SCF_SUCCESS) {
			ret = scf_error();
			goto error;
		}

		for (;;) {
			ret = scf_iter_next_instance(iter, inst);
			if (ret == 0)
				break;
			if (ret != 1) {
				ret = scf_error();
				goto error;
			}

			if (scf_instance_to_fmri(inst, fmri,
			    max_fmri_length + 1) == -1)
				goto badfmri;

			if ((ret = scf_add_match(htable, fmri, NULL,
			    &pattern[i], flags & SCF_WALK_EXPLICIT)) != 0)
				goto error;
		}

		if ((pattern[i].sp_arg = strdup(argv[i])) == NULL) {
			ret = SCF_ERROR_NO_MEMORY;
			goto error;
		}
		pattern[i].sp_type = PATTERN_EXACT;
		partial_fmri = B_TRUE;	/* we just iterated all instances */

		continue;

badfmri:

		/*
		 * If we got here because of a fatal error, bail out
		 * immediately.
		 */
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN) {
			ret = scf_error();
			goto error;
		}

		/*
		 * At this point we failed to interpret the argument as a
		 * complete fmri, so mark it as a partial or globbed FMRI for
		 * later processing.
		 */
		if (strpbrk(argv[i], "*?[") != NULL) {
			/*
			 * Prepend svc:/ to patterns which don't begin with * or
			 * svc: or lrc:.
			 */
			wildcard_fmri = B_TRUE;
			pattern[i].sp_type = PATTERN_GLOB;
			if (argv[i][0] == '*' ||
			    (strlen(argv[i]) >= 4 && argv[i][3] == ':'))
				pattern[i].sp_arg = strdup(argv[i]);
			else {
				pattern[i].sp_arg = malloc(strlen(argv[i]) + 6);
				if (pattern[i].sp_arg != NULL)
					(void) snprintf(pattern[i].sp_arg,
					    strlen(argv[i]) + 6, "svc:/%s",
					    argv[i]);
			}
		} else {
			partial_fmri = B_TRUE;
			pattern[i].sp_type = PATTERN_PARTIAL;
			pattern[i].sp_arg = strdup(argv[i]);
		}
		pattern_search = 1;
		if (pattern[i].sp_arg == NULL) {
			ret = SCF_ERROR_NO_MEMORY;
			goto error;
		}
	}

	if (pattern_search || argc == 0) {
		/*
		 * We have a set of patterns to search for.  Iterate over all
		 * instances and legacy services searching for matches.
		 */
		if (scf_handle_get_local_scope(h, scope) != 0) {
			ret = scf_error();
			goto error;
		}

		if (scf_iter_scope_services(sciter, scope) != 0) {
			ret = scf_error();
			goto error;
		}

		for (;;) {
			ret = scf_iter_next_service(sciter, svc);
			if (ret == 0)
				break;
			if (ret != 1) {
				ret = scf_error();
				goto error;
			}

			if (flags & SCF_WALK_SERVICE) {
				/*
				 * If the user is requesting bare services, try
				 * to match the service first.
				 */
				if (scf_service_to_fmri(svc, fmri,
				    max_fmri_length + 1) < 0) {
					ret = scf_error();
					goto error;
				}

				if (argc == 0) {
					info.fmri = fmri;
					info.scope = scope;
					info.svc = svc;
					info.inst = NULL;
					info.pg = NULL;
					info.prop = NULL;
					if ((ret = callback(data, &info)) != 0)
						goto error;
					continue;
				} else if ((ret = scf_pattern_match(htable,
				    fmri, NULL, argc, pattern,
				    flags & SCF_WALK_EXPLICIT)) != 0) {
					goto error;
				}
			}

			if (flags & SCF_WALK_NOINSTANCE)
				continue;

			/*
			 * Iterate over all instances in the service.
			 */
			if (scf_iter_service_instances(siter, svc) != 0) {
				if (scf_error() != SCF_ERROR_DELETED) {
					ret = scf_error();
					goto error;
				}
				continue;
			}

			for (;;) {
				ret = scf_iter_next_instance(siter, inst);
				if (ret == 0)
					break;
				if (ret != 1) {
					if (scf_error() != SCF_ERROR_DELETED) {
						ret = scf_error();
						goto error;
					}
					break;
				}

				if (scf_instance_to_fmri(inst, fmri,
				    max_fmri_length + 1) < 0) {
					ret = scf_error();
					goto error;
				}

				/*
				 * Without arguments, execute the callback
				 * immediately.
				 */
				if (argc == 0) {
					info.fmri = fmri;
					info.scope = scope;
					info.svc = svc;
					info.inst = inst;
					info.pg = NULL;
					info.prop = NULL;
					if ((ret = callback(data, &info)) != 0)
						goto error;
				} else if ((ret = scf_pattern_match(htable,
				    fmri, NULL, argc, pattern,
				    flags & SCF_WALK_EXPLICIT)) != 0) {
					goto error;
				}
			}
		}

		/*
		 * Search legacy services
		 */
		if ((flags & SCF_WALK_LEGACY)) {
			if (scf_scope_get_service(scope, SCF_LEGACY_SERVICE,
			    svc) != 0) {
				if (scf_error() != SCF_ERROR_NOT_FOUND) {
					ret = scf_error();
					goto error;
				}

				goto nolegacy;
			}

			if (scf_iter_service_pgs_typed(iter, svc,
			    SCF_GROUP_FRAMEWORK) != SCF_SUCCESS) {
				ret = scf_error();
				goto error;
			}

			(void) strcpy(fmri, LEGACY_SCHEME);

			for (;;) {
				ret = scf_iter_next_pg(iter, pg);
				if (ret == -1) {
					ret = scf_error();
					goto error;
				}
				if (ret == 0)
					break;

				if (scf_pg_get_property(pg,
				    SCF_LEGACY_PROPERTY_NAME, prop) == -1) {
					ret = scf_error();
					if (ret == SCF_ERROR_DELETED ||
					    ret == SCF_ERROR_NOT_FOUND) {
						ret = 0;
						continue;
					}
					goto error;
				}

				if (scf_property_is_type(prop, SCF_TYPE_ASTRING)
				    != SCF_SUCCESS) {
					if (scf_error() == SCF_ERROR_DELETED)
						continue;
					ret = scf_error();
					goto error;
				}

				if (scf_property_get_value(prop, value) !=
				    SCF_SUCCESS)
					continue;

				if (scf_value_get_astring(value,
				    fmri + sizeof (LEGACY_SCHEME) - 1,
				    max_fmri_length + 2 -
				    sizeof (LEGACY_SCHEME)) <= 0)
					continue;

				if (scf_pg_get_name(pg, pgname,
				    max_name_length + 1) <= 0) {
					if (scf_error() == SCF_ERROR_DELETED)
						continue;
					ret = scf_error();
					goto error;
				}

				if (argc == 0) {
					info.fmri = fmri;
					info.scope = scope;
					info.svc = NULL;
					info.inst = NULL;
					info.pg = pg;
					info.prop = NULL;
					if ((ret = callback(data, &info)) != 0)
						goto error;
				} else if ((ret = scf_pattern_match(htable,
				    fmri, pgname, argc, pattern,
				    flags & SCF_WALK_EXPLICIT)) != 0)
					goto error;
			}

		}
	}
nolegacy:
	ret = 0;

	if (argc == 0)
		goto error;

	/*
	 * Check all patterns, and see if we have that any that didn't match
	 * or any that matched multiple instances.  For svcprop, add up the
	 * total number of matching keys.
	 */
	info.count = 0;
	for (i = 0; i < argc; i++) {
		scf_match_t *match;

		if (pattern[i].sp_type == PATTERN_INVALID)
			continue;
		if (pattern[i].sp_matchcount == 0) {
			scf_msg_t msgid;
			/*
			 * Provide a useful error message based on the argument
			 * and the type of entity requested.
			 */
			if (!(flags & SCF_WALK_LEGACY) &&
			    strncmp(pattern[i].sp_arg, "lrc:/", 5) == 0)
				msgid = SCF_MSG_PATTERN_LEGACY;
			else if (flags & SCF_WALK_PROPERTY)
				msgid = SCF_MSG_PATTERN_NOENTITY;
			else if (flags & SCF_WALK_NOINSTANCE)
				msgid = SCF_MSG_PATTERN_NOSERVICE;
			else if (flags & SCF_WALK_SERVICE)
				msgid = SCF_MSG_PATTERN_NOINSTSVC;
			else
				msgid = SCF_MSG_PATTERN_NOINSTANCE;

			errfunc(scf_get_msg(msgid), pattern[i].sp_arg);
			if (err)
				*err = UU_EXIT_FATAL;
		} else if (!(flags & SCF_WALK_MULTIPLE) &&
		    pattern[i].sp_matchcount > 1) {
			size_t len, off;
			char *msg;

			/*
			 * Construct a message with all possible FMRIs before
			 * passing off to error handling function.
			 *
			 * Note that strlen(scf_get_msg(...)) includes the
			 * length of '%s', which accounts for the terminating
			 * null byte.
			 */
			len = strlen(scf_get_msg(SCF_MSG_PATTERN_MULTIMATCH)) +
			    strlen(pattern[i].sp_arg);
			for (match = pattern[i].sp_matches; match != NULL;
			    match = match->sm_next) {
				len += strlen(match->sm_key->sk_fmri) + 2;
			}
			if ((msg = malloc(len)) == NULL) {
				ret = SCF_ERROR_NO_MEMORY;
				goto error;
			}

			/* LINTED - format argument */
			(void) snprintf(msg, len,
			    scf_get_msg(SCF_MSG_PATTERN_MULTIMATCH),
			    pattern[i].sp_arg);
			off = strlen(msg);
			for (match = pattern[i].sp_matches; match != NULL;
			    match = match->sm_next) {
				off += snprintf(msg + off, len - off, "\t%s\n",
				    match->sm_key->sk_fmri);
			}

			errfunc(msg);
			if (err != NULL)
				*err = UU_EXIT_FATAL;

			free(msg);
		} else {
			for (match = pattern[i].sp_matches; match != NULL;
			    match = match->sm_next) {
				if (!match->sm_key->sk_seen)
					info.count++;
				match->sm_key->sk_seen = 1;
			}
		}
	}

	if (flags & SCF_WALK_UNIPARTIAL && info.count > 1) {
		/*
		 * If the SCF_WALK_UNIPARTIAL flag was passed in and we have
		 * more than one fmri, then this is an error if we matched
		 * because of a partial fmri parameter, unless we also matched
		 * more than one fmri because of wildcards in the parameters.
		 * That is, the presence of wildcards indicates that it is ok
		 * to match more than one fmri in this case.
		 * For example, a parameter of 'foo' that matches more than
		 * one fmri is an error, but parameters of 'foo *bar*' that
		 * matches more than one is fine.
		 */
		if (partial_fmri && !wildcard_fmri) {
			errfunc(scf_get_msg(SCF_MSG_PATTERN_MULTIPARTIAL));
			if (err != NULL)
				*err = UU_EXIT_FATAL;
			goto error;
		}
	}

	/*
	 * Clear 'sk_seen' for all keys.
	 */
	for (i = 0; i < WALK_HTABLE_SIZE; i++) {
		scf_matchkey_t *key;
		for (key = htable[i]; key != NULL; key = key->sk_next)
			key->sk_seen = 0;
	}

	/*
	 * Iterate over all the FMRIs in our hash table and execute the
	 * callback.
	 */
	for (i = 0; i < argc; i++) {
		scf_match_t *match;
		scf_matchkey_t *key;

		/*
		 * Ignore patterns which didn't match anything or matched too
		 * many FMRIs.
		 */
		if (pattern[i].sp_matchcount == 0 ||
		    (!(flags & SCF_WALK_MULTIPLE) &&
		    pattern[i].sp_matchcount > 1))
			continue;

		for (match = pattern[i].sp_matches; match != NULL;
		    match = match->sm_next) {

			key = match->sm_key;
			if (key->sk_seen)
				continue;

			key->sk_seen = 1;

			if (key->sk_legacy != NULL) {
				if (scf_scope_get_service(scope,
				    "smf/legacy_run", svc) != 0) {
					ret = scf_error();
					goto error;
				}

				if (scf_service_get_pg(svc, key->sk_legacy,
				    pg) != 0)
					continue;

				info.fmri = key->sk_fmri;
				info.scope = scope;
				info.svc = NULL;
				info.inst = NULL;
				info.pg = pg;
				info.prop = NULL;
				if ((ret = callback(data, &info)) != 0)
					goto error;
			} else {
				if (scf_handle_decode_fmri(h, key->sk_fmri,
				    scope, svc, inst, pg, prop, 0) !=
				    SCF_SUCCESS)
					continue;

				info.fmri = key->sk_fmri;
				info.scope = scope;
				info.svc = svc;
				if (scf_instance_get_name(inst, NULL, 0) < 0) {
					if (scf_error() ==
					    SCF_ERROR_CONNECTION_BROKEN) {
						ret = scf_error();
						goto error;
					}
					info.inst = NULL;
				} else {
					info.inst = inst;
				}
				if (scf_pg_get_name(pg, NULL, 0) < 0) {
					if (scf_error() ==
					    SCF_ERROR_CONNECTION_BROKEN) {
						ret = scf_error();
						goto error;
					}
					info.pg = NULL;
				} else {
					info.pg = pg;
				}
				if (scf_property_get_name(prop, NULL, 0) < 0) {
					if (scf_error() ==
					    SCF_ERROR_CONNECTION_BROKEN) {
						ret = scf_error();
						goto error;
					}
					info.prop = NULL;
				} else {
					info.prop = prop;
				}

				if ((ret = callback(data, &info)) != 0)
					goto error;
			}
		}
	}

error:
	if (htable) {
		scf_matchkey_t *key, *next;

		for (i = 0; i < WALK_HTABLE_SIZE; i++) {

			for (key = htable[i]; key != NULL;
			    key = next) {

				next = key->sk_next;

				if (key->sk_fmri != NULL)
					free(key->sk_fmri);
				if (key->sk_legacy != NULL)
					free(key->sk_legacy);
				free(key);
			}
		}
		free(htable);
	}
	if (pattern != NULL) {
		for (i = 0; i < argc; i++) {
			scf_match_t *match, *next;

			if (pattern[i].sp_arg != NULL)
				free(pattern[i].sp_arg);

			for (match = pattern[i].sp_matches; match != NULL;
			    match = next) {

				next = match->sm_next;

				free(match);
			}
		}
		free(pattern);
	}

	free(fmri);
	free(pgname);

	scf_value_destroy(value);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_scope_destroy(scope);
	scf_iter_destroy(siter);
	scf_iter_destroy(sciter);
	scf_iter_destroy(iter);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);

	return (ret);
}

/*
 * scf_encode32() is an implementation of Base32 encoding as described in
 * section 6 of RFC 4648 - "The Base16, Base32, and Base64 Data
 * Encodings". See http://www.ietf.org/rfc/rfc4648.txt?number=4648.  The
 * input stream is divided into groups of 5 characters (40 bits).  Each
 * group is encoded into 8 output characters where each output character
 * represents 5 bits of input.
 *
 * If the input is not an even multiple of 5 characters, the output will be
 * padded so that the output is an even multiple of 8 characters.  The
 * standard specifies that the pad character is '='.  Unfortunately, '=' is
 * not a legal character in SMF property names.  Thus, the caller can
 * specify an alternate pad character with the pad argument.  If pad is 0,
 * scf_encode32() will use '='.  Note that use of anything other than '='
 * produces output that is not in conformance with RFC 4648.  It is
 * suitable, however, for internal use of SMF software.  When the encoded
 * data is used as part of an SMF property name, SCF_ENCODE32_PAD should be
 * used as the pad character.
 *
 * Arguments:
 *	input -		Address of the buffer to be encoded.
 *	inlen -		Number of characters at input.
 *	output -	Address of the buffer to receive the encoded data.
 *	outmax -	Size of the buffer at output.
 *	outlen -	If it is not NULL, outlen receives the number of
 *			bytes placed in output.
 *	pad -		Alternate padding character.
 *
 * Returns:
 *	0	Buffer was successfully encoded.
 *	-1	Indicates output buffer too small, or pad is one of the
 *		standard encoding characters.
 */
int
scf_encode32(const char *input, size_t inlen, char *output, size_t outmax,
    size_t *outlen, char pad)
{
	uint_t group_size = 5;
	uint_t i;
	const unsigned char *in = (const unsigned char *)input;
	size_t olen;
	uchar_t *out = (uchar_t *)output;
	uint_t oval;
	uint_t pad_count;

	/* Verify that there is enough room for the output. */
	olen = ((inlen + (group_size - 1)) / group_size) * 8;
	if (outlen)
		*outlen = olen;
	if (olen > outmax)
		return (-1);

	/* If caller did not provide pad character, use the default. */
	if (pad == 0) {
		pad = '=';
	} else {
		/*
		 * Make sure that caller's pad is not one of the encoding
		 * characters.
		 */
		for (i = 0; i < sizeof (base32) - 1; i++) {
			if (pad == base32[i])
				return (-1);
		}
	}

	/* Process full groups capturing 5 bits per output character. */
	for (; inlen >= group_size; in += group_size, inlen -= group_size) {
		/*
		 * The comments in this section number the bits in an
		 * 8 bit byte 0 to 7.  The high order bit is bit 7 and
		 * the low order bit is bit 0.
		 */

		/* top 5 bits (7-3) from in[0] */
		*out++ = base32[in[0] >> 3];
		/* bits 2-0 from in[0] and top 2 (7-6) from in[1] */
		*out++ = base32[((in[0] << 2) & 0x1c) | (in[1] >> 6)];
		/* 5 bits (5-1) from in[1] */
		*out++ = base32[(in[1] >> 1) & 0x1f];
		/* low bit (0) from in[1] and top 4 (7-4) from in[2] */
		*out++ = base32[((in[1] << 4) & 0x10) | ((in[2] >> 4) & 0xf)];
		/* low 4 (3-0) from in[2] and top bit (7) from in[3] */
		*out++ = base32[((in[2] << 1) & 0x1e) | (in[3] >> 7)];
		/* 5 bits (6-2) from in[3] */
		*out++ = base32[(in[3] >> 2) & 0x1f];
		/* low 2 (1-0) from in[3] and top 3 (7-5) from in[4] */
		*out++ = base32[((in[3] << 3) & 0x18) | (in[4] >> 5)];
		/* low 5 (4-0) from in[4] */
		*out++ = base32[in[4] & 0x1f];
	}

	/* Take care of final input bytes. */
	pad_count = 0;
	if (inlen) {
		/* top 5 bits (7-3) from in[0] */
		*out++ = base32[in[0] >> 3];
		/*
		 * low 3 (2-0) from in[0] and top 2 (7-6) from in[1] if
		 * available.
		 */
		oval = (in[0] << 2) & 0x1c;
		if (inlen == 1) {
			*out++ = base32[oval];
			pad_count = 6;
			goto padout;
		}
		oval |= in[1] >> 6;
		*out++ = base32[oval];
		/* 5 bits (5-1) from in[1] */
		*out++ = base32[(in[1] >> 1) & 0x1f];
		/*
		 * low bit (0) from in[1] and top 4 (7-4) from in[2] if
		 * available.
		 */
		oval = (in[1] << 4) & 0x10;
		if (inlen == 2) {
			*out++ = base32[oval];
			pad_count = 4;
			goto padout;
		}
		oval |= in[2] >> 4;
		*out++ = base32[oval];
		/*
		 * low 4 (3-0) from in[2] and top 1 (7) from in[3] if
		 * available.
		 */
		oval = (in[2] << 1) & 0x1e;
		if (inlen == 3) {
			*out++ = base32[oval];
			pad_count = 3;
			goto padout;
		}
		oval |= in[3] >> 7;
		*out++ = base32[oval];
		/* 5 bits (6-2) from in[3] */
		*out++ = base32[(in[3] >> 2) & 0x1f];
		/* low 2 bits (1-0) from in[3] */
		*out++ = base32[(in[3] << 3) & 0x18];
		pad_count = 1;
	}
padout:
	/*
	 * Pad the output so that it is a multiple of 8 bytes.
	 */
	for (; pad_count > 0; pad_count--) {
		*out++ = pad;
	}

	/*
	 * Null terminate the output if there is enough room.
	 */
	if (olen < outmax)
		*out = 0;

	return (0);
}

/*
 * scf_decode32() is an implementation of Base32 decoding as described in
 * section 6 of RFC 4648 - "The Base16, Base32, and Base64 Data
 * Encodings". See http://www.ietf.org/rfc/rfc4648.txt?number=4648.  The
 * input stream is divided into groups of 8 encoded characters.  Each
 * encoded character represents 5 bits of data.  Thus, the 8 encoded
 * characters are used to produce 40 bits or 5 bytes of unencoded data in
 * outbuf.
 *
 * If the encoder did not have enough data to generate a mulitple of 8
 * characters of encoded data, it used a pad character to get to the 8
 * character boundry. The standard specifies that the pad character is '='.
 * Unfortunately, '=' is not a legal character in SMF property names.
 * Thus, the caller can specify an alternate pad character with the pad
 * argument.  If pad is 0, scf_decode32() will use '='.  Note that use of
 * anything other than '=' is not in conformance with RFC 4648.  It is
 * suitable, however, for internal use of SMF software.  When the encoded
 * data is used in SMF property names, SCF_ENCODE32_PAD should be used as
 * the pad character.
 *
 * Arguments:
 *	in -		Buffer of encoded characters.
 *	inlen -		Number of characters at in.
 *	outbuf -	Buffer to receive the decoded bytes.  It can be the
 *			same buffer as in.
 *	outmax -	Size of the buffer at outbuf.
 *	outlen -	If it is not NULL, outlen receives the number of
 *			bytes placed in output.
 *	pad -		Alternate padding character.
 *
 * Returns:
 *	0	Buffer was successfully decoded.
 *	-1	Indicates an invalid input character, output buffer too
 *		small, or pad is one of the standard encoding characters.
 */
int
scf_decode32(const char *in, size_t inlen, char *outbuf, size_t outmax,
    size_t *outlen, char pad)
{
	char *bufend = outbuf + outmax;
	char c;
	uint_t count;
	uint32_t g[DECODE32_GS];
	size_t i;
	uint_t j;
	char *out = outbuf;
	boolean_t pad_seen = B_FALSE;

	/* If caller did not provide pad character, use the default. */
	if (pad == 0) {
		pad = '=';
	} else {
		/*
		 * Make sure that caller's pad is not one of the encoding
		 * characters.
		 */
		for (i = 0; i < sizeof (base32) - 1; i++) {
			if (pad == base32[i])
				return (-1);
		}
	}

	i = 0;
	while ((i < inlen) && (out < bufend)) {
		/* Get a group of input characters. */
		for (j = 0, count = 0;
		    (j < DECODE32_GS) && (i < inlen);
		    i++) {
			c = in[i];
			/*
			 * RFC 4648 allows for the encoded data to be split
			 * into multiple lines, so skip carriage returns
			 * and new lines.
			 */
			if ((c == '\r') || (c == '\n'))
				continue;
			if ((pad_seen == B_TRUE) && (c != pad)) {
				/* Group not completed by pads */
				return (-1);
			}
			if ((c < 0) || (c >= sizeof (index32))) {
				/* Illegal character. */
				return (-1);
			}
			if (c == pad) {
				pad_seen = B_TRUE;
				continue;
			}
			if ((g[j++] = index32[c]) == 0xff) {
				/* Illegal character */
				return (-1);
			}
			count++;
		}

		/* Pack the group into five 8 bit bytes. */
		if ((count >= 2) && (out < bufend)) {
			/*
			 * Output byte 0:
			 *	5 bits (7-3) from g[0]
			 *	3 bits (2-0) from g[1] (4-2)
			 */
			*out++ = (g[0] << 3) | ((g[1] >> 2) & 0x7);
		}
		if ((count >= 4) && (out < bufend)) {
			/*
			 * Output byte 1:
			 *	2 bits (7-6) from g[1] (1-0)
			 *	5 bits (5-1) from g[2] (4-0)
			 *	1 bit (0) from g[3] (4)
			 */
			*out++ = (g[1] << 6) | (g[2] << 1) | \
			    ((g[3] >> 4) & 0x1);
		}
		if ((count >= 5) && (out < bufend)) {
			/*
			 * Output byte 2:
			 *	4 bits (7-4) from g[3] (3-0)
			 *	4 bits (3-0) from g[4] (4-1)
			 */
			*out++ = (g[3] << 4) | ((g[4] >> 1) & 0xf);
		}
		if ((count >= 7) && (out < bufend)) {
			/*
			 * Output byte 3:
			 *	1 bit (7) from g[4] (0)
			 *	5 bits (6-2) from g[5] (4-0)
			 *	2 bits (0-1) from g[6] (4-3)
			 */
			*out++ = (g[4] << 7) | (g[5] << 2) |
			    ((g[6] >> 3) & 0x3);
		}
		if ((count == 8) && (out < bufend)) {
			/*
			 * Output byte 4;
			 *	3 bits (7-5) from g[6] (2-0)
			 *	5 bits (4-0) from g[7] (4-0)
			 */
			*out++ = (g[6] << 5) | g[7];
		}
	}
	if (i < inlen) {
		/* Did not process all input characters. */
		return (-1);
	}
	if (outlen)
		*outlen = out - outbuf;
	/* Null terminate the output if there is room. */
	if (out < bufend)
		*out = 0;
	return (0);
}


/*
 * _scf_request_backup:  a simple wrapper routine
 */
int
_scf_request_backup(scf_handle_t *h, const char *name)
{
	struct rep_protocol_backup_request request;
	struct rep_protocol_response response;

	int r;

	if (strlcpy(request.rpr_name, name, sizeof (request.rpr_name)) >=
	    sizeof (request.rpr_name))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	(void) pthread_mutex_lock(&h->rh_lock);
	request.rpr_request = REP_PROTOCOL_BACKUP;
	request.rpr_changeid = handle_next_changeid(h);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0) {
		DOOR_ERRORS_BLOCK(r);
	}

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));
	return (SCF_SUCCESS);
}

/*
 * Request svc.configd daemon to switch repository database.
 *
 * Can fail:
 *
 *	_NOT_BOUND		handle is not bound
 *	_CONNECTION_BROKEN	server is not reachable
 *	_INTERNAL		file operation error
 *				the server response is too big
 *	_PERMISSION_DENIED	not enough privileges to do request
 *	_BACKEND_READONLY	backend is not writable
 *	_BACKEND_ACCESS		backend access fails
 *	_NO_RESOURCES		svc.configd is out of memory
 */
int
_scf_repository_switch(scf_handle_t *h, int scf_sw)
{
	struct rep_protocol_switch_request request;
	struct rep_protocol_response response;
	int	r;

	/*
	 * Setup request protocol and make door call
	 * Hold rh_lock lock before handle_next_changeid call
	 */
	(void) pthread_mutex_lock(&h->rh_lock);

	request.rpr_flag = scf_sw;
	request.rpr_request = REP_PROTOCOL_SWITCH;
	request.rpr_changeid = handle_next_changeid(h);

	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));

	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0) {
		DOOR_ERRORS_BLOCK(r);
	}

	/*
	 * Pass protocol error up
	 */
	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));

	return (SCF_SUCCESS);
}

int
_scf_pg_is_read_protected(const scf_propertygroup_t *pg, boolean_t *out)
{
	char buf[REP_PROTOCOL_NAME_LEN];
	ssize_t res;

	res = datael_get_name(&pg->rd_d, buf, sizeof (buf),
	    RP_ENTITY_NAME_PGREADPROT);

	if (res == -1)
		return (-1);

	if (uu_strtouint(buf, out, sizeof (*out), 0, 0, 1) == -1)
		return (scf_set_error(SCF_ERROR_INTERNAL));
	return (SCF_SUCCESS);
}

/*
 * _scf_set_annotation: a wrapper to set the annotation fields for SMF
 * security auditing.
 *
 * Fails with following in scf_error_key thread specific data:
 *	_INVALID_ARGUMENT - operation or file too large
 *	_NOT_BOUND
 *	_CONNECTION_BROKEN
 *	_INTERNAL
 *	_NO_RESOURCES
 */
int
_scf_set_annotation(scf_handle_t *h, const char *operation, const char *file)
{
	struct rep_protocol_annotation request;
	struct rep_protocol_response response;
	size_t copied;
	int r;

	if (h == NULL) {
		/* We can't do anything if the handle is destroyed. */
		return (scf_set_error(SCF_ERROR_HANDLE_DESTROYED));
	}

	request.rpr_request = REP_PROTOCOL_SET_AUDIT_ANNOTATION;
	copied = strlcpy(request.rpr_operation,
	    (operation == NULL) ? "" : operation,
	    sizeof (request.rpr_operation));
	if (copied >= sizeof (request.rpr_operation))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	copied = strlcpy(request.rpr_file,
	    (file == NULL) ? "" : file,
	    sizeof (request.rpr_file));
	if (copied >= sizeof (request.rpr_file))
		return (scf_set_error(SCF_ERROR_INVALID_ARGUMENT));

	(void) pthread_mutex_lock(&h->rh_lock);
	r = make_door_call(h, &request, sizeof (request),
	    &response, sizeof (response));
	(void) pthread_mutex_unlock(&h->rh_lock);

	if (r < 0) {
		DOOR_ERRORS_BLOCK(r);
	}

	if (response.rpr_response != REP_PROTOCOL_SUCCESS)
		return (scf_set_error(proto_error(response.rpr_response)));
	return (0);
}
