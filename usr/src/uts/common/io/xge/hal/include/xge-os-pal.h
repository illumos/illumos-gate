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
 *
 * Copyright (c) 2002-2006 Neterion, Inc.
 */

#ifndef XGE_OS_PAL_H
#define XGE_OS_PAL_H

#include "xge-defs.h"

__EXTERN_BEGIN_DECLS

/*--------------------------- platform switch ------------------------------*/

/* platform specific header */
#include "xge_osdep.h"

#if !defined(XGE_OS_PLATFORM_64BIT) && !defined(XGE_OS_PLATFORM_32BIT)
#error "either 32bit or 64bit switch must be defined!"
#endif

#if !defined(XGE_OS_HOST_BIG_ENDIAN) && !defined(XGE_OS_HOST_LITTLE_ENDIAN)
#error "either little endian or big endian switch must be defined!"
#endif

#if defined(XGE_OS_PLATFORM_64BIT)
#define XGE_OS_MEMORY_DEADCODE_PAT	0x5a5a5a5a5a5a5a5a
#else
#define XGE_OS_MEMORY_DEADCODE_PAT	0x5a5a5a5a
#endif

#define XGE_OS_TRACE_MSGBUF_MAX		512
typedef struct xge_os_tracebuf_t {
	int		wrapped_once;
	int		timestamp;
	volatile int	offset;
	int		size;
	char		msg[XGE_OS_TRACE_MSGBUF_MAX];
	char		*data;
} xge_os_tracebuf_t;
extern xge_os_tracebuf_t *g_xge_os_tracebuf;

#ifdef XGE_TRACE_INTO_CIRCULAR_ARR
extern xge_os_tracebuf_t *g_xge_os_tracebuf;
extern char *dmesg_start;

#define __xge_trace(tb) { \
	int msgsize = xge_os_strlen(tb->msg) + 1; \
	int offset = tb->offset; \
	if (msgsize != 1 && msgsize < XGE_OS_TRACE_MSGBUF_MAX) { \
		int leftsize =  tb->size - offset; \
		if ((msgsize + XGE_OS_TRACE_MSGBUF_MAX) > leftsize) { \
			xge_os_memzero(tb->data + offset, leftsize); \
			offset = 0; \
			tb->wrapped_once = 1; \
		} \
		xge_os_memcpy(tb->data + offset, tb->msg, msgsize); \
		offset += msgsize; \
		tb->offset = offset; \
		dmesg_start = tb->data + offset; \
		*tb->msg = 0; \
	} \
}

#define xge_os_vatrace(tb, fmt) { \
	if (tb != NULL) { \
		char *_p = tb->msg; \
		if (tb->timestamp) { \
			xge_os_timestamp(tb->msg); \
			_p = tb->msg + xge_os_strlen(tb->msg); \
		} \
		xge_os_vasprintf(_p, fmt); \
		__xge_trace(tb); \
	} \
}

#ifdef __GNUC__
#define xge_os_trace(tb, fmt...) { \
	if (tb != NULL) { \
		if (tb->timestamp) { \
			xge_os_timestamp(tb->msg); \
		} \
		xge_os_sprintf(tb->msg + xge_os_strlen(tb->msg), fmt); \
		__xge_trace(tb); \
	} \
}
#endif /* __GNUC__ */

#else
#define xge_os_vatrace(tb, fmt)
#ifdef __GNUC__
#define xge_os_trace(tb, fmt...)
#endif /* __GNUC__ */
#endif

__EXTERN_END_DECLS

#endif /* XGE_OS_PAL_H */
