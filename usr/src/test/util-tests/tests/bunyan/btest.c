/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

#include <stdio.h>
#include <assert.h>
#include <bunyan.h>
#include <netinet/in.h>
#include <strings.h>

static void
create_handles(void)
{
	bunyan_logger_t *a, *b, *c;

	assert(bunyan_init("foo", &a) == 0);
	assert(bunyan_init("foo", &b) == 0);
	assert(bunyan_init("foo", &c) == 0);
	bunyan_fini(a);
	bunyan_fini(b);
	bunyan_fini(c);
}

static void
create_stream(void)
{
	bunyan_logger_t *a;

	assert(bunyan_init("foo", &a) == 0);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "baz", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == EEXIST);
	assert(bunyan_stream_add(a, "baz", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == EEXIST);
	assert(bunyan_stream_remove(a, "baz") == 0);
	assert(bunyan_stream_remove(a, "baz") == ENOENT);
	assert(bunyan_stream_remove(a, "foobaz") == ENOENT);
	assert(bunyan_stream_remove(a, "blah") == ENOENT);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == EEXIST);
	assert(bunyan_stream_add(a, "baz", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "debug", BUNYAN_L_DEBUG,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "info", BUNYAN_L_INFO,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "warn", BUNYAN_L_WARN,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "error", BUNYAN_L_ERROR,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_stream_add(a, "fatal", BUNYAN_L_FATAL,
	    bunyan_stream_fd, (void *)1) == 0);

	bunyan_fini(a);
}

static void
create_key(void)
{
	bunyan_logger_t *a;
	struct in_addr v4;
	struct in6_addr v6;

	assert(bunyan_init("foo", &a) == 0);
	assert(bunyan_key_remove(a, "blah") == ENOENT);
	assert(bunyan_key_add(a, BUNYAN_T_END) == 0);

	assert(bunyan_key_add(a, BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);

	assert(bunyan_key_remove(a, "s") == 0);
	assert(bunyan_key_remove(a, "s") == ENOENT);
	assert(bunyan_key_remove(a, "p") == 0);
	assert(bunyan_key_remove(a, "p") == ENOENT);
	assert(bunyan_key_remove(a, "v4") == 0);
	assert(bunyan_key_remove(a, "v4") == ENOENT);
	assert(bunyan_key_remove(a, "v6") == 0);
	assert(bunyan_key_remove(a, "v6") == ENOENT);
	assert(bunyan_key_remove(a, "b") == 0);
	assert(bunyan_key_remove(a, "b") == ENOENT);
	assert(bunyan_key_remove(a, "i32") == 0);
	assert(bunyan_key_remove(a, "i32") == ENOENT);
	assert(bunyan_key_remove(a, "i64") == 0);
	assert(bunyan_key_remove(a, "i64") == ENOENT);
	assert(bunyan_key_remove(a, "u32") == 0);
	assert(bunyan_key_remove(a, "u32") == ENOENT);
	assert(bunyan_key_remove(a, "u64") == 0);
	assert(bunyan_key_remove(a, "u64") == ENOENT);
	assert(bunyan_key_remove(a, "d") == 0);
	assert(bunyan_key_remove(a, "d") == ENOENT);
	assert(bunyan_key_remove(a, "i64s") == 0);
	assert(bunyan_key_remove(a, "i64s") == ENOENT);
	assert(bunyan_key_remove(a, "u64s") == 0);
	assert(bunyan_key_remove(a, "u64s") == ENOENT);

	bunyan_fini(a);
}

static void
bad_level(void)
{
	bunyan_logger_t *a;

	assert(bunyan_init("bad level", &a) == 0);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_TRACE - 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_TRACE + 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_DEBUG - 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_INFO + 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_WARN - 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_ERROR + 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", BUNYAN_L_FATAL - 1,
	    bunyan_stream_fd, (void *)1) == EINVAL);
	assert(bunyan_stream_add(a, "bar", -5,
	    bunyan_stream_fd, (void *)1) == EINVAL);

	bunyan_fini(a);
}

static void
basic_log(void)
{
	bunyan_logger_t *a;

	assert(bunyan_init("basic", &a) == 0);
	assert(bunyan_stream_add(a, "foo", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_trace(a, "trace", BUNYAN_T_END) == 0);
	assert(bunyan_debug(a, "debug", BUNYAN_T_END) == 0);
	assert(bunyan_info(a, "info", BUNYAN_T_END) == 0);
	assert(bunyan_warn(a, "warn", BUNYAN_T_END) == 0);
	assert(bunyan_error(a, "error", BUNYAN_T_END) == 0);
	assert(bunyan_fatal(a, "fatal", BUNYAN_T_END) == 0);

	bunyan_fini(a);
}

static void
crazy_log(void)
{
	bunyan_logger_t *a;
	struct in_addr v4;
	struct in6_addr v6;

	bzero(&v4, sizeof (struct in_addr));
	bzero(&v6, sizeof (struct in6_addr));

	assert(bunyan_init("basic", &a) == 0);
	assert(bunyan_stream_add(a, "foo", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_trace(a, "trace", BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);
	assert(bunyan_debug(a, "debug", BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);
	assert(bunyan_info(a, "info", BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);
	assert(bunyan_warn(a, "warn", BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);
	assert(bunyan_error(a, "error", BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);
	assert(bunyan_fatal(a, "fatal", BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);

	bunyan_fini(a);
}

static void
child_log(void)
{
	bunyan_logger_t *a, *child;
	struct in_addr v4;
	struct in6_addr v6;

	bzero(&v4, sizeof (struct in_addr));
	bzero(&v6, sizeof (struct in6_addr));

	assert(bunyan_init("child", &a) == 0);
	assert(bunyan_stream_add(a, "foo", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_child(a, &child,  BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);

	bunyan_fini(a);
	assert(bunyan_trace(child, "trace", BUNYAN_T_END) == 0);
	assert(bunyan_debug(child, "debug", BUNYAN_T_END) == 0);
	assert(bunyan_info(child, "info", BUNYAN_T_END) == 0);
	assert(bunyan_warn(child, "warn", BUNYAN_T_END) == 0);
	assert(bunyan_error(child, "error", BUNYAN_T_END) == 0);
	assert(bunyan_fatal(child, "fatal", BUNYAN_T_END) == 0);

	bunyan_fini(child);
}

static void
crazy_child(void)
{
	bunyan_logger_t *a, *child;
	struct in_addr v4;
	struct in6_addr v6;

	bzero(&v4, sizeof (struct in_addr));
	bzero(&v6, sizeof (struct in6_addr));

	assert(bunyan_init("crazy child", &a) == 0);
	assert(bunyan_stream_add(a, "foo", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_key_add(a, BUNYAN_T_STRING, "s", "foo",
	    BUNYAN_T_POINTER, "p", (void *)a, BUNYAN_T_IP, "v4", &v4,
	    BUNYAN_T_IP6, "v6", &v6, BUNYAN_T_BOOLEAN, "b", B_TRUE,
	    BUNYAN_T_INT32, "i32", 69, BUNYAN_T_INT64, "i64", (uint64_t)6969,
	    BUNYAN_T_UINT32, "u32", 23, BUNYAN_T_UINT64, "u64", (uint64_t)2323,
	    BUNYAN_T_DOUBLE, "d", 3.14,
	    BUNYAN_T_INT64STR, "i64s", (uint64_t)12345,
	    BUNYAN_T_UINT64STR, "u64s", (uint64_t)54321, BUNYAN_T_END) == 0);
	assert(bunyan_child(a, &child, BUNYAN_T_END) == 0);
	bunyan_fini(a);

	assert(bunyan_stream_remove(child, "foo") == 0);
	assert(bunyan_stream_add(child, "bar", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)1) == 0);
	assert(bunyan_key_remove(child, "u64s") == 0);
	assert(bunyan_trace(child, "trace", BUNYAN_T_END) == 0);
	assert(bunyan_debug(child, "debug", BUNYAN_T_END) == 0);
	assert(bunyan_info(child, "info", BUNYAN_T_END) == 0);
	assert(bunyan_warn(child, "warn", BUNYAN_T_END) == 0);
	assert(bunyan_error(child, "error", BUNYAN_T_END) == 0);
	assert(bunyan_fatal(child, "fatal", BUNYAN_T_END) == 0);

	bunyan_fini(child);
}

int
main(void)
{
	create_handles();
	create_stream();
	create_key();
	bad_level();
	basic_log();
	crazy_log();
	child_log();
	crazy_child();

	return (0);
}
