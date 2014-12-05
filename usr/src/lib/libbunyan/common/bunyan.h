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

#ifndef _BUNYAN_H
#define	_BUNYAN_H

/*
 * C version of the bunyan logging format.
 */

#include <limits.h>
#include <libnvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bunyan_logger bunyan_logger_t;

typedef enum bunyan_level {
	BUNYAN_L_TRACE	= 10,
	BUNYAN_L_DEBUG 	= 20,
	BUNYAN_L_INFO	= 30,
	BUNYAN_L_WARN	= 40,
	BUNYAN_L_ERROR	= 50,
	BUNYAN_L_FATAL	= 60
} bunyan_level_t;

typedef enum bunyan_type {
	BUNYAN_T_END	= 0x0,
	BUNYAN_T_STRING,
	BUNYAN_T_POINTER,
	BUNYAN_T_IP,
	BUNYAN_T_IP6,
	BUNYAN_T_BOOLEAN,
	BUNYAN_T_INT32,
	BUNYAN_T_INT64,
	BUNYAN_T_UINT32,
	BUNYAN_T_UINT64,
	BUNYAN_T_DOUBLE,
	BUNYAN_T_INT64STR,
	BUNYAN_T_UINT64STR
} bunyan_type_t;

/*
 * A handle is MT-safe, but not fork-safe.
 */
extern int bunyan_init(const char *, bunyan_logger_t **);
extern int bunyan_child(const bunyan_logger_t *, bunyan_logger_t **, ...);
extern void bunyan_fini(bunyan_logger_t *);

/*
 * Bunyan stream callbacks are guaranteed to be serialized.
 */
typedef int (*bunyan_stream_f)(nvlist_t *, const char *, void *);
extern int bunyan_stream_fd(nvlist_t *, const char *, void *);

extern int bunyan_stream_add(bunyan_logger_t *, const char *, int,
    bunyan_stream_f, void *);
extern int bunyan_stream_remove(bunyan_logger_t *, const char *);

extern int bunyan_key_add(bunyan_logger_t *, ...);
extern int bunyan_key_remove(bunyan_logger_t *, const char *);

extern int bunyan_trace(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_debug(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_info(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_warn(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_error(bunyan_logger_t *, const char *msg, ...);
extern int bunyan_fatal(bunyan_logger_t *, const char *msg, ...);

#ifdef __cplusplus
}
#endif

#endif /* _BUNYAN_H */
